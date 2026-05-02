use crate::cryptography;
use crate::ctaphid::CtapStatus;
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
use passkeyd_abi::config::Config;
use passkeyd_abi::database;
use passkeyd_abi::database::layout::{OtherUI, Passkey};
use passkeyd_abi::utils::Cose;
use passkeyd_abi::utils::UI;
use passkeyd_abi::utils::spawn_ui;
use serde::Serialize;

use super::{ALGO_ES256, ALGO_RS256};
use log::{debug, info};
use sha2::Digest;

pub fn make(config: &Config, req: Request) -> anyhow::Result<Response> {
    if let (Some(exclude_list), Some((_, passkeys))) =
        (req.exclude_list, database::get_passkeys(&req.rp))
    {
        let exists = exclude_list.iter().any(|desc| {
            passkeys
                .iter()
                .any(|key| *desc.id == key.credential_source.id)
        });

        if exists {
            // optional todo!: asking for user presence using passkey selection before proceeding
            anyhow::bail!(CtapStatus::CredentialExcluded);
        }
    }

    let mut crypto = cryptography::resolve_cryptography(config);
    let algos = req.pub_key_cred_params.0;

    let (crypto_pair, cose) = if algos
        .contains(&webauthn::KnownPublicKeyCredentialParameters { alg: ALGO_ES256 })
    {
        // let it crash
        crypto.generate_es256_keypair().unwrap()
    } else if algos.contains(&webauthn::KnownPublicKeyCredentialParameters { alg: ALGO_RS256 }) {
        crypto.generate_rs256_keypair().unwrap()
    } else {
        anyhow::bail!(CtapStatus::UnsupportedAlgorithm)
    };

    debug!("Generated wrapped private and public keys");

    let passkey = Passkey::new(req.rp.id.clone(), req.user.clone(), crypto_pair);

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

    let (sign_alg, sign) = crypto.sign_payload(
        passkey.credential_source.crypto_pair.clone(),
        &signed_payload,
    )?;

    let mut res = ResponseBuilder {
        auth_data: authenticator_data
            .serialize()
            .expect("failed to searialize"),
        fmt: AttestationStatementFormat::Packed,
    }
    .build();

    res.att_stmt = Some(AttestationStatement::Packed(PackedAttestationStatement {
        alg: sign_alg,
        sig: Bytes::from_slice(&sign).expect("Unexpected number of bytes"),
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

    let cerds_ui = AuthorizationUI {
        rp: &req.rp,
        other_ui: &passkey.credential_source.other_ui,
    };

    let presence_ui = SelectionUI {
        title: &passkeyd_locale::translate!("passkeyd.cerds.make.presence_ui.title"),
        description: &passkeyd_locale::translate!("passkeyd.cerds.make.presence_ui.description"),
        button: &passkeyd_locale::translate!("passkeyd.cerds.make.presence_ui.button"),
    };

    // In CTAP2.0, a MakeCredential request is sent as a backward-compatible replacement for the Selection command.
    // https://source.chromium.org/chromium/chromium/src/+/main:device/fido/make_credential_task.cc;drc=eb40dba9a062951578292de39424d7479f723463;l=66

    let is_selection_request = matches!(req.rp.id.as_str(), ".dummy" | "make.me.blink");

    let mut ui_handle = if is_selection_request {
        spawn_ui(config, UI::KeySelection, presence_ui)
    } else {
        spawn_ui(config, UI::KeyEnroll, cerds_ui)
    };

    let result = ui_handle.wait().expect("failed to collect UI response");

    if result.code().unwrap_or_default() != 0 {
        info!("Authorization denied");
        anyhow::bail!(CtapStatus::OperationDenied);
    }

    if !is_selection_request {
        passkey.store(req.rp);
    }

    Ok(res)
}

#[derive(Serialize)]
pub struct AuthorizationUI<'a> {
    pub rp: &'a PublicKeyCredentialRpEntity,
    pub other_ui: &'a OtherUI,
}

#[derive(Serialize)]
pub struct SelectionUI<'a> {
    pub description: &'a str,
    pub title: &'a str,
    pub button: &'a str,
}
