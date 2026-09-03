use crate::cryptography;
use crate::ctaphid::CtapStatus;
use crate::ctaphid::ctaphid::Ctaphid;
use crate::utils::cancellable_ui;
use crate::utils::has_another_fido_device;

use std::process::ExitStatus;

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
use ctaphid_types::Channel;
use passkeyd_abi::config::Config;
use passkeyd_abi::cryptography::CryptoBackend;
use passkeyd_abi::cryptography::CryptoPair;
use passkeyd_abi::database;
use passkeyd_abi::database::layout::Passkey;
use passkeyd_abi::utils::Cose;
use passkeyd_abi::utils::EnrollUI;
use passkeyd_abi::utils::PresenceUI;
use passkeyd_abi::utils::UI;
use passkeyd_abi::utils::spawn_ui;

use super::{ALGO_ES256, ALGO_RS256};
use log::{debug, info};
use sha2::Digest;

pub fn make(
    hid: &mut Ctaphid,
    channel: Channel,
    config: &Config,
    req: Request,
) -> anyhow::Result<Response> {
    check_excluded_credential(hid, channel, config, &req)?;

    let mut crypto = cryptography::resolve_cryptography(config);
    let (crypto_pair, credential_public_key) = generate_credentials(crypto.as_mut(), &req)?;
    debug!("Generated wrapped private and public keys");
    let passkey = Passkey::new(req.rp.id.clone(), req.user.clone(), crypto_pair);

    let attested_credential = AttestedCredentialData {
        aaguid: &[0u8; 16],
        credential_id: &passkey.credential_source.id,
        credential_public_key: match &credential_public_key {
            Cose::ES256(key) => key.as_slice(),
            Cose::RS256(key) => key.as_slice(),
        },
    };

    let rp_id_hash = sha2::Sha256::digest(req.rp.id.as_bytes()).into();

    let authenticator_data: AuthenticatorData<'_, AttestedCredentialData<'_>, Extensions> =
        AuthenticatorData {
            sign_count: passkey.sign_count,
            attested_credential_data: Some(attested_credential),
            flags: AuthenticatorDataFlags::ATTESTED_CREDENTIAL_DATA
                | AuthenticatorDataFlags::USER_PRESENCE
                | AuthenticatorDataFlags::USER_VERIFIED,
            rp_id_hash: &rp_id_hash,
            extensions: None,
        };

    let auth_data_bytes = authenticator_data.serialize().unwrap();
    let mut signed_payload = auth_data_bytes.to_vec();
    signed_payload.extend_from_slice(req.client_data_hash);

    let (sign_algo, sign) = crypto.sign_payload(
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
        alg: sign_algo,
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

    // In CTAP2.0, a MakeCredential request is sent as a backward-compatible replacement for the Selection command.
    // https://source.chromium.org/chromium/chromium/src/+/main:device/fido/make_credential_task.cc;drc=eb40dba9a062951578292de39424d7479f723463;l=66

    let is_selection_req = matches!(req.rp.id.as_str(), ".dummy" | "make.me.blink");

    let status = if is_selection_req {
        request_selection(hid, channel, config)?
    } else {
        cancellable_ui(
            hid,
            channel,
            spawn_ui(
                config,
                UI::KeyEnroll,
                EnrollUI {
                    rp: &req.rp,
                    other_ui: &passkey.credential_source.other_ui,
                },
            ),
        )?
        .exit_status
    };

    if !status.success() {
        info!("Authorization denied");
        anyhow::bail!(CtapStatus::OperationDenied);
    }

    if !is_selection_req {
        passkey.store(req.rp);
    }

    Ok(res)
}

fn check_excluded_credential(
    hid: &mut Ctaphid,
    channel: Channel,
    config: &Config,
    req: &Request,
) -> anyhow::Result<()> {
    let Some(exclude_list) = &req.exclude_list else {
        return Ok(());
    };

    let Some((_, passkeys)) = database::get_passkeys(&req.rp) else {
        return Ok(());
    };

    let excluded = exclude_list.iter().any(|descriptor| {
        passkeys
            .iter()
            .any(|passkey| *descriptor.id == passkey.credential_source.id)
    });

    if !excluded {
        return Ok(());
    }

    // If another authenticator is present, ask the user persence
    if has_another_fido_device() {
        request_selection(hid, channel, config)?;

        info!("Excluded credential detected");
    }

    anyhow::bail!(CtapStatus::CredentialExcluded);
}

fn request_selection(
    hid: &mut Ctaphid,
    channel: Channel,
    config: &Config,
) -> anyhow::Result<ExitStatus> {
    Ok(cancellable_ui(
        hid,
        channel,
        spawn_ui(
            config,
            UI::KeySelection,
            PresenceUI {
                title: &passkeyd_locale::translate!("passkeyd.cerds.make.presence_ui.title"),
                description: &passkeyd_locale::translate!(
                    "passkeyd.cerds.make.presence_ui.description"
                ),
                button: &passkeyd_locale::translate!("passkeyd.cerds.make.presence_ui.button"),
            },
        ),
    )?
    .exit_status)
}

fn generate_credentials(
    crypto: &mut dyn CryptoBackend,
    req: &Request,
) -> anyhow::Result<(CryptoPair, Cose)> {
    let algos = &req.pub_key_cred_params.0;

    if algos.contains(&webauthn::KnownPublicKeyCredentialParameters { alg: ALGO_ES256 }) {
        return crypto.generate_es256_keypair().map_err(anyhow::Error::msg);
    }

    if algos.contains(&webauthn::KnownPublicKeyCredentialParameters { alg: ALGO_RS256 }) {
        return crypto.generate_rs256_keypair().map_err(anyhow::Error::msg);
    }

    anyhow::bail!(CtapStatus::UnsupportedAlgorithm);
}
