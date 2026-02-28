use std::mem::MaybeUninit;

use ctap_types::{
    Bytes,
    ctap2::{
        AuthenticatorDataFlags,
        get_assertion::{self, Request, Response, ResponseBuilder},
    },
    webauthn::PublicKeyCredentialRpEntity,
};
use log::{error, info};
use pam::Client;
use serde::Serialize;
use sha2::Digest;

use crate::{cerds::translate_es256_to_der, ctaphid::CtapStatus, tpm};

use passkeyd_share::{
    config::Config,
    database::{
        get_passkeys,
        layout::{OtherUI, Passkey},
    }, utils::{UI, spawn_ui},
};

pub fn get(config: &Config, req: Request) -> anyhow::Result<Response> {
    let mut passkeys = Vec::new();

    // mock PublicKeyCredentialRpEntity, will be overriden by actuall PublicKeyCredentialRpEntity
    let mut rp_entity = PublicKeyCredentialRpEntity {
        icon: None,
        id: req.rp_id.into(),
        name: None,
    };

    let user_selected = Some(req.allow_list.is_none());

    match req.allow_list {
        Some(allow_cred) if allow_cred.len() > 0 => {
            for cred in allow_cred {
                if let Some((rp, passkey)) = Passkey::get(&rp_entity, &cred.id) {
                    rp_entity = rp;
                    passkeys.push(passkey)
                }
            }
        }
        Some(_) => {
            if let Some((rp, stored_passkeys)) = get_passkeys(&rp_entity) {
                rp_entity = rp;
                passkeys.extend(stored_passkeys);
            }
        }
        None => {
            if let Some((rp, stored_passkeys)) = get_passkeys(&rp_entity) {
                rp_entity = rp;
                passkeys.extend(stored_passkeys);
            }
        }
    };

    if passkeys.len() < 1 {
        anyhow::bail!(CtapStatus::NoCredentials)
    }

    let ui_state = AuthorizationUI {
        rp: &rp_entity,
        other_uis: passkeys
            .iter()
            .map(|x| &x.credential_source.other_ui)
            .collect::<Vec<_>>(),
    };

    let ui = spawn_ui(config, UI::KeySelect, ui_state);
    let result = ui
        .wait_with_output()
        .expect("failed to collect ui response");
    let stdout = &result.stdout;

    let data_slice = if result.status.success()
        && let Some(start_of_the_text) = stdout.iter().position(|&x| x == 0x02)
    {
        if let Some(end_of_the_text) = stdout[start_of_the_text + 1..]
            .iter()
            .position(|&x| x == 0x03)
        {
            let end_pos = start_of_the_text + 1 + end_of_the_text;
            &stdout[start_of_the_text + 1..end_pos]
        } else {
            anyhow::bail!(CtapStatus::OperationDenied)
        }
    } else {
        info!("The request was denied");
        anyhow::bail!(CtapStatus::KeepaliveCancel)
    };

    let authorized_idx = usize::from_le_bytes(data_slice[..size_of::<usize>()].try_into().unwrap());
    let password = String::from_utf8_lossy(&data_slice[size_of::<usize>()..]).to_string();

    // client isn't expected to send a username.
    let Some(login_user) = get_username_from_uid(config.gui_uid) else {
        error!("Failed to find username.");
        anyhow::bail!(CtapStatus::OperationDenied)
    };

    let mut client = Client::with_password("system-auth").expect("Failed to init PAM client!");
    client
        .conversation_mut()
        .set_credentials(login_user, password);
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
        anyhow::bail!(CtapStatus::UvBlocked)
    }

    let authorized_passkey = passkeys
        .drain(authorized_idx..=authorized_idx)
        .next()
        .unwrap();

    let hash_result = sha2::Sha256::digest(req.rp_id.as_bytes());
    let rp_id_hash_array = hash_result.into();

    let authenticator_data = get_assertion::AuthenticatorData {
        attested_credential_data: None,
        extensions: None,
        flags: AuthenticatorDataFlags::USER_VERIFIED | AuthenticatorDataFlags::USER_PRESENCE,
        rp_id_hash: &rp_id_hash_array,
        sign_count: authorized_passkey.sign_count + 1,
    };

    let auth_data_bytes = authenticator_data.serialize().unwrap();
    let mut signed_payload = auth_data_bytes.to_vec();
    signed_payload.extend_from_slice(&req.client_data_hash);

    let mut ctx = tpm::initialize_tpm_with_session()?;
    let srk_key_handle = tpm::create_primary_key_handle(&mut ctx)?;

    let signature = tpm::sign(
        &mut ctx,
        &srk_key_handle,
        authorized_passkey
            .credential_source
            .private_key
            .clone()
            .try_into()
            .unwrap(),
        authorized_passkey
            .credential_source
            .public_key
            .clone()
            .try_into()
            .unwrap(),
        &mut signed_payload,
    )?;

    let sig_bytes = match signature {
        tss_esapi::structures::Signature::EcDsa(sig) => {
            translate_es256_to_der(sig.signature_r().as_slice(), sig.signature_s().as_slice())
        }
        tss_esapi::structures::Signature::RsaSsa(sig) => sig.signature().to_vec(),
        _ => unreachable!(),
    };

    let mut response = ResponseBuilder {
        auth_data: authenticator_data.serialize().expect("failed to serialize"),
        credential: ctap_types::webauthn::PublicKeyCredentialDescriptor {
            id: Bytes::from_slice(&authorized_passkey.credential_source.id).unwrap(),
            key_type: "public-key".into(),
        },
        signature: Bytes::from_slice(&sig_bytes).expect("Unexpected number of bytes"),
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
    response.user_selected = user_selected;
    authorized_passkey.sign_increment(rp_entity);
    Ok(response)
}

#[derive(Serialize)]
pub struct AuthorizationUI<'a> {
    pub rp: &'a PublicKeyCredentialRpEntity,
    pub other_uis: Vec<&'a OtherUI>,
}

fn get_username_from_uid<'a>(uid: libc::uid_t) -> Option<String> {
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
