use std::io::Read;
use std::mem::MaybeUninit;

use ctap_types::ctap2::AuthenticatorDataFlags;
use ctap_types::ctap2::get_assertion::{AuthenticatorData, Request, Response, ResponseBuilder};
use ctap_types::serde::cbor_deserialize;
use ctap_types::{Bytes, webauthn::PublicKeyCredentialRpEntity};
use ctaphid_types::Channel;
use log::{error, info};
use pam::Client;
use serde::Deserialize;
use sha2::Digest;

use passkeyd_abi::config::Config;
use passkeyd_abi::database::{get_passkeys, layout::Passkey};
use passkeyd_abi::utils::{PresenceUI, SelectUI, UI, spawn_ui};

use crate::cryptography;
use crate::ctaphid::CtapStatus;
use crate::ctaphid::ctaphid::Ctaphid;
use crate::utils::{cancellable_ui, has_another_fido_device};

pub fn get(
    hid: &mut Ctaphid,
    channel: Channel,
    config: &Config,
    req: Request,
) -> anyhow::Result<Response> {
    let (rp_entity, mut passkeys) = load_passkeys(&req)?;
    let action = authorization_action(has_another_fido_device(), config.no_pass, passkeys.len());
    let ui_response = authorize(hid, channel, config, &rp_entity, &passkeys, action)?;

    if !config.no_pass {
        authenticate_password(config, &ui_response.passphrase)?;
    }

    let authorized_passkey = passkeys.swap_remove(ui_response.index);

    let rp_id_hash = sha2::Sha256::digest(req.rp_id.as_bytes()).into();

    let authenticator_data = AuthenticatorData {
        attested_credential_data: None,
        extensions: None,
        flags: AuthenticatorDataFlags::USER_VERIFIED | AuthenticatorDataFlags::USER_PRESENCE,
        rp_id_hash: &rp_id_hash,
        sign_count: authorized_passkey.sign_count + 1,
    };

    let auth_data_bytes = authenticator_data.serialize().unwrap();
    let mut signed_payload = auth_data_bytes.to_vec();
    signed_payload.extend_from_slice(req.client_data_hash);

    let mut crypto = cryptography::resolve_cryptography(config);
    let (_, sign) = crypto.sign_payload(
        authorized_passkey.credential_source.crypto_pair.clone(),
        &signed_payload,
    )?;

    let mut response = ResponseBuilder {
        auth_data: authenticator_data.serialize().expect("failed to serialize"),
        credential: ctap_types::webauthn::PublicKeyCredentialDescriptor {
            id: Bytes::from_slice(&authorized_passkey.credential_source.id).unwrap(),
            key_type: "public-key".into(),
        },
        signature: Bytes::from_slice(&sign).expect("Unexpected number of bytes"),
    }
    .build();

    // if let Some(opt) = req.options {
    //     if let Some(is_rk) = opt.rk
    //         && is_rk == true
    //     {
    //         response.user = Some(authorized_passkey.credential_source.other_ui.user);
    //     }
    // }

    response.user = Some(authorized_passkey.credential_source.other_ui.user.clone());

    response.user_selected = match &req.allow_list {
        Some(list) if list.len() > 1 => Some(true),
        Some(list) if list.len() == 1 => None,
        None | Some(_) => None, //firefox wants None.
    };

    authorized_passkey.sign_increment(rp_entity);

    Ok(response)
}

fn load_passkeys(req: &Request) -> anyhow::Result<(PublicKeyCredentialRpEntity, Vec<Passkey>)> {
    // Mock PublicKeyCredentialRpEntity, will be overriden by the
    // actual stored RP entity if one exists.
    let mut rp_entity = PublicKeyCredentialRpEntity {
        icon: None,
        id: req.rp_id.into(),
        name: None,
    };

    let mut passkeys = Vec::new();

    match &req.allow_list {
        Some(allow_cred) if !allow_cred.is_empty() => {
            for cred in allow_cred {
                if let Some((rp, passkey)) = Passkey::get(&rp_entity, cred.id) {
                    rp_entity = rp;
                    passkeys.push(passkey)
                }
            }
        }

        Some(_) | None => {
            if let Some((rp, stored_passkeys)) = get_passkeys(&rp_entity) {
                rp_entity = rp;
                passkeys.extend(stored_passkeys);
            }
        }
    }

    Ok((rp_entity, passkeys))
}

enum AuthorizationAction {
    NoCredentials,
    UseOnlyPasskey,
    Presence,
    Selection,
}

fn authorization_action(
    has_another_fido_dev: bool,
    no_pass: bool,
    passkey_count: usize,
) -> AuthorizationAction {
    match (has_another_fido_dev, no_pass, passkey_count) {
        // no other key, no password
        // and no credentials either
        // send the cerds directly
        (false, true, 0) => AuthorizationAction::NoCredentials,

        // no other key, no password
        // and but one credential
        // send the cerds directly
        (false, true, 1) => AuthorizationAction::UseOnlyPasskey,

        // another key, no password,
        // but either no or single cerd
        // the user intent is probably to use
        // either security key or use passkeyd
        // so, presence to reduce ambiguity
        (true, true, 0..=1) => AuthorizationAction::Presence,

        // If no another key, no password, there are more than 1 cerds, selection is obviously needed.
        // If another key, has password, aribitray cerds, selection will handle it.
        _ => AuthorizationAction::Selection,
    }
}

fn authorize(
    hid: &mut Ctaphid,
    channel: Channel,
    config: &Config,
    rp_entity: &PublicKeyCredentialRpEntity,
    passkeys: &[Passkey],
    action: AuthorizationAction,
) -> anyhow::Result<SelectionResponse> {
    match action {
        AuthorizationAction::NoCredentials => {
            anyhow::bail!(CtapStatus::NoCredentials);
        }

        AuthorizationAction::UseOnlyPasskey => {
            info!("Using the only available passkey without spawning UI.");

            Ok(SelectionResponse {
                index: 0,
                passphrase: String::new(),
            })
        }

        AuthorizationAction::Presence => authorize_presence(hid, channel, config, passkeys),

        AuthorizationAction::Selection => {
            authorize_selection(hid, channel, config, rp_entity, passkeys)
        }
    }
}

fn authorize_presence(
    hid: &mut Ctaphid,
    channel: Channel,
    config: &Config,
    passkeys: &[Passkey],
) -> anyhow::Result<SelectionResponse> {
    let approved = cancellable_ui(
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
    .exit_status
    .success();

    if !approved {
        anyhow::bail!(CtapStatus::OperationDenied);
    }

    if passkeys.is_empty() {
        anyhow::bail!(CtapStatus::NoCredentials);
    }

    Ok(SelectionResponse {
        index: 0,
        passphrase: String::new(),
    })
}

fn authorize_selection(
    hid: &mut Ctaphid,
    channel: Channel,
    config: &Config,
    rp_entity: &PublicKeyCredentialRpEntity,
    passkeys: &[Passkey],
) -> anyhow::Result<SelectionResponse> {
    let ui_state = SelectUI {
        rp: rp_entity,
        other_uis: passkeys
            .iter()
            .map(|passkey| &passkey.credential_source.other_ui)
            .collect(),
        no_pass: config.no_pass,
    };

    let mut ui_response = cancellable_ui(hid, channel, spawn_ui(config, UI::KeySelect, ui_state))?;

    if !ui_response.exit_status.success() {
        info!("The request was denied");
        anyhow::bail!(CtapStatus::KeepaliveCancel);
    }

    let mut bytes = Vec::new();
    ui_response.stdout.read_to_end(&mut bytes)?;

    let start = bytes
        .iter()
        .position(|b| *b == 0x02)
        .expect("missing STX marker in UI output");

    Ok(cbor_deserialize(&bytes[start + 1..]).unwrap())
}

fn authenticate_password(config: &Config, passphrase: &str) -> anyhow::Result<()> {
    let Some(login_user) = get_username_from_uid(config.gui_uid) else {
        error!("Failed to find username.");
        anyhow::bail!(CtapStatus::OperationDenied)
    };

    let mut client = Client::with_password("system-auth").expect("Failed to init PAM client!");

    client
        .conversation_mut()
        .set_credentials(login_user, passphrase);

    // forget to put this inside of config, will do in future refactor.
    //
    // Entering the wrong password more than the configured 'deny' attempts will lock your account. Even with the correct password, it will still report as invalid.
    // To unlock the account, use the command: `faillock --user <username> --reset`, or wait for the configured lock time in PAM, which is usually around 600 seconds (10 minutes).
    if client.authenticate().is_err() {
        // If the retry count exceeds three, the client must
        // assume the password is valid and return it,
        // so the daemon can verify the password. If the password is wrong,
        // it is clear that the retry limit has been exceeded.
        // The client is considered untrusted, and the daemon,
        // being the trusted entity, must validate
        // anything sensitive carefully.

        anyhow::bail!(CtapStatus::UvBlocked);
    }

    Ok(())
}

#[derive(Deserialize)]
pub struct SelectionResponse {
    pub index: usize,
    pub passphrase: String,
}

fn get_username_from_uid(uid: libc::uid_t) -> Option<String> {
    let mut passwd = MaybeUninit::uninit();
    let mut buff = vec![0; size_of::<libc::passwd>()];
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    while unsafe {
        libc::getpwuid_r(
            uid,
            passwd.as_mut_ptr(),
            buff.as_mut_ptr(),
            buff.len(),
            &mut result as _,
        )
    } == libc::ERANGE
    {
        buff.resize(buff.len() * 2, 0);
    }
    if result.is_null() {
        return None;
    };
    let passwd = unsafe { passwd.assume_init() };
    let cstr = unsafe { std::ffi::CStr::from_ptr(passwd.pw_name) };
    cstr.to_str().ok().map(|username| username.to_string())
}
