use super::{spawn_ui, translate_es256_to_der};
use crate::config::Config;
use crate::ctaphid::CtapStatus;
use crate::database::layout::{Cose, OtherUI, Passkey, encode_cose_es256, encode_cose_rs256};
use crate::tpm;
use ctap_types::Bytes;
use ctap_types::ctap2::AttestationStatement;
use ctap_types::ctap2::AttestationStatementFormat;
use ctap_types::ctap2::AuthenticatorData;
use ctap_types::ctap2::AuthenticatorDataFlags;
use ctap_types::ctap2::PackedAttestationStatement;
use ctap_types::ctap2::make_credential::AttestedCredentialData;
use ctap_types::ctap2::make_credential::Extensions;
use ctap_types::ctap2::make_credential::Request;
use ctap_types::ctap2::make_credential::Response;
use ctap_types::ctap2::make_credential::ResponseBuilder;
use ctap_types::webauthn;
use ctap_types::webauthn::PublicKeyCredentialRpEntity;
use serde::Serialize;

use super::{ALGO_ES256, ALGO_RS256};
use log::{debug, info};
use sha2::Digest;

pub fn make(config: &Config, req: Request) -> anyhow::Result<Response> {
    // https://source.chromium.org/chromium/chromium/src/+/main:device/fido/make_credential_task.cc;drc=eb40dba9a062951578292de39424d7479f723463;l=66
    // todo!(): handle .dummy request from chromium.

    let mut ctx = tpm::initialize_tpm_with_session()?;
    let srk_key_handle = tpm::create_primary_key_handle(&mut ctx)?;
    let algos = req.pub_key_cred_params.0;
    let (privte_key, public_key, cose) = if algos
        .contains(&webauthn::KnownPublicKeyCredentialParameters { alg: ALGO_ES256 })
    {
        let (pr, pu) = tpm::es256::make_cerd(&mut ctx, &srk_key_handle)?;
        match &pu {
            tss_esapi::structures::Public::Ecc {
                object_attributes: _,
                name_hashing_algorithm: _,
                auth_policy: _,
                parameters: _,
                unique,
            } => {
                let cose = encode_cose_es256(
                    unique.x().as_array().unwrap(),
                    unique.y().as_array().unwrap(),
                );
                (pr, pu, cose)
            }
            _ => unreachable!(),
        }
    } else if algos.contains(&webauthn::KnownPublicKeyCredentialParameters { alg: ALGO_RS256 }) {
        let (pr, pu) = tpm::rs256::make_cerd(&mut ctx, &srk_key_handle)?;
        match &pu {
            tss_esapi::structures::Public::Rsa {
                object_attributes: _,
                name_hashing_algorithm: _,
                auth_policy: _,
                parameters,
                unique,
            } => {
                let e: [u8; 4] = parameters.exponent().value().to_be_bytes();
                let n = unique.value().as_array().unwrap();
                let cose = encode_cose_rs256(n, &e[1..].as_array().unwrap());
                (pr, pu, cose)
            }
            _ => unreachable!(),
        }
    } else {
        anyhow::bail!(CtapStatus::UnsupportedAlgorithm)
    };

    debug!("Generated wrapped private and public keys");

    let passkey = Passkey::new(privte_key, public_key, req.rp.id.clone(), req.user.clone());

    let attested_credential = AttestedCredentialData {
        aaguid: &[0u8; 16],
        credential_id: &passkey.credential_source.id,
        credential_public_key: match &cose {
            Cose::ES256(c) => c.as_slice(),
            Cose::RS256(c) => c.as_slice(),
        },
    };

    let hash_result = sha2::Sha256::digest(req.rp.id.as_bytes());
    let rp_id_hash_array = hash_result.into();

    let authenticator_data: AuthenticatorData<'_, AttestedCredentialData<'_>, Extensions> =
        AuthenticatorData {
            sign_count: passkey.sign_count,
            attested_credential_data: Some(attested_credential),
            flags: AuthenticatorDataFlags::ATTESTED_CREDENTIAL_DATA
                | AuthenticatorDataFlags::USER_PRESENCE
                | AuthenticatorDataFlags::USER_VERIFIED,
            rp_id_hash: &rp_id_hash_array,
            extensions: None,
        };

    let auth_data_bytes = authenticator_data.serialize().unwrap();
    let mut signed_payload = auth_data_bytes.to_vec();
    signed_payload.extend_from_slice(req.client_data_hash);

    let signature = tpm::sign(
        &mut ctx,
        &srk_key_handle,
        passkey
            .credential_source
            .private_key
            .clone()
            .try_into()
            .unwrap(),
        passkey
            .credential_source
            .public_key
            .clone()
            .try_into()
            .unwrap(),
        &mut signed_payload,
    )?;

    let (alg, sig_bytes) = match signature {
        tss_esapi::structures::Signature::EcDsa(sig) => (
            -7,
            translate_es256_to_der(sig.signature_r().as_slice(), sig.signature_s().as_slice()),
        ),
        tss_esapi::structures::Signature::RsaSsa(sig) => (-257, sig.signature().to_vec()),
        _ => unreachable!(),
    };

    let mut res = ResponseBuilder {
        auth_data: authenticator_data
            .serialize()
            .expect("failed to searialize"),
        fmt: AttestationStatementFormat::Packed,
    }
    .build();

    res.att_stmt = Some(AttestationStatement::Packed(PackedAttestationStatement {
        alg,
        sig: Bytes::from_slice(&sig_bytes).expect("Unexpected number of bytes"),
        x5c: None,
    }));

    // todo!()
    // if let Some(ext) = req.extensions {
    // }>

    // todo!()
    // if let Some(c) = req.attestation_formats_preference {
    //     let formats = c.known_formats();
    //     if formats.len() >= 0 && formats.contains(&AttestationStatementFormat::Packed) {
    //         res.fmt = AttestationStatementFormat::Packed;
    //     }
    // }

    // todo!()
    // if let Some(_) = req.enterprise_attestation {
    //     res.ep_att = Some(false);
    // }

    info!("Extensions and attestations are ignored, not yst supported");

    info!("Looking for user authorization...");

    let ui_state = AuthorizationUI {
        rp: &req.rp,
        other_ui: &passkey.credential_source.other_ui,
    };

    let mut ui = spawn_ui(config, crate::cerds::UI::KeyEnroll, ui_state);
    let result = ui.wait().expect("failed to collect ui response");
    if result.code().unwrap_or_default() != 0 {
        info!("Authorization denied");
        anyhow::bail!(CtapStatus::OperationDenied);
    }
    passkey.store(req.rp);
    Ok(res)
}

#[derive(Serialize)]
pub struct AuthorizationUI<'a> {
    pub rp: &'a PublicKeyCredentialRpEntity,
    pub other_ui: &'a OtherUI, //todo!(): clean up OtherUI, and use from shared lib instead
}
