use std::io::{Read, Write};
use std::mem::MaybeUninit;
use std::process::{ChildStdin, ChildStdout};
use std::sync::mpsc::{self, TryRecvError};
use std::time::Duration;

use anyhow::Context;
use ctap_types::ctap2::AuthenticatorDataFlags;
use ctap_types::ctap2::get_assertion::{AuthenticatorData, Request, Response, ResponseBuilder};
use ctap_types::serde::cbor_deserialize;
use ctap_types::{Bytes, webauthn::PublicKeyCredentialRpEntity};
use ctaphid_types::{Channel, DeviceError};
use log::{debug, error, info};
use sha2::Digest;

use passkeyd_abi::config::{Auth, Config};
use passkeyd_abi::database::{get_passkeys, layout::Passkey};
use passkeyd_abi::utils::{
    CborVec, FallbackToPasswordReason, PresenceUI, SelectUI, ServiceMessage, SystemdChild, UI,
    UIMessage, spawn_ui,
};
use zbus::blocking::Connection;

use crate::auth::fprintd::{FprintDeviceProxyBlocking, FprintManagerProxyBlocking};
use crate::auth::pam::InteractiveConversation;
use crate::auth::pass::verify_password;
use crate::cryptography;
use crate::ctaphid::ctaphid::Ctaphid;
use crate::ctaphid::{CtapStatus, TransportError};
use crate::utils::{Readiness, cancellable_ui, has_another_fido_device};

pub fn get(
    hid: &mut Ctaphid,
    channel: Channel,
    config: &Config,
    req: Request,
) -> anyhow::Result<Response> {
    let (rp_entity, mut passkeys) = load_passkeys(&req)?;
    let action = authorization_action(has_another_fido_device(), config.no_pass, passkeys.len());
    let authorized_index = authorize(hid, channel, config, &rp_entity, &passkeys, action)?;
    let authorized_passkey = passkeys.swap_remove(authorized_index);

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
    //      }
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
        // send the no cerds directly
        (false, true, 0) => AuthorizationAction::NoCredentials,

        // no other key, no password
        // and but one credential
        // skip ui, send the cerds directly
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
) -> anyhow::Result<usize> {
    match action {
        AuthorizationAction::NoCredentials => {
            anyhow::bail!(CtapStatus::NoCredentials);
        }

        AuthorizationAction::UseOnlyPasskey => {
            info!("Using the only available passkey without spawning UI.");
            Ok(0)
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
) -> anyhow::Result<usize> {
    let ui_data = PresenceUI {
        title: &passkeyd_locale::translate!("passkeyd.cerds.make.presence_ui.title"),
        description: &passkeyd_locale::translate!("passkeyd.cerds.make.presence_ui.description"),
        button: &passkeyd_locale::translate!("passkeyd.cerds.make.presence_ui.button"),
    };

    let approved = cancellable_ui(hid, channel, spawn_ui(config, UI::KeySelection, ui_data))?
        .exit_status
        .success();

    if !approved {
        anyhow::bail!(CtapStatus::OperationDenied);
    }

    if passkeys.is_empty() {
        anyhow::bail!(CtapStatus::NoCredentials);
    }

    Ok(0)
}

fn authorize_selection(
    hid: &mut Ctaphid,
    channel: Channel,
    config: &Config,
    rp_entity: &PublicKeyCredentialRpEntity,
    passkeys: &[Passkey],
) -> anyhow::Result<usize> {
    let ui_state = SelectUI {
        rp: rp_entity,
        other_uis: passkeys
            .iter()
            .map(|passkey| &passkey.credential_source.other_ui)
            .collect(),
        no_pass: config.no_pass,
    };

    authenticate_handler(hid, channel, config, ui_state)
}

#[derive(Debug)]
enum AuthorizationOutcome {
    Authorized,
    UnAuthorized,
    FallbackToPassword(FallbackToPasswordReason),
}

fn authenticate_handler(
    hid: &mut Ctaphid,
    channel: Channel,
    config: &Config,
    ui_state: SelectUI,
) -> anyhow::Result<usize> {
    let mut child = spawn_ui(config, UI::KeySelect, ui_state);
    let mut stdin = child.inner.stdin.take().unwrap();
    let mut stdout = child.inner.stdout.take().unwrap();
    let mut event_buf = Vec::new();

    loop {
        if let Some(event) = try_ui_message(hid, channel, &mut child, &mut stdout, &mut event_buf)?
        {
            match event {
                UIMessage::SelectionDoneMaybeStartAuth(i) => {
                    if !config.no_pass {
                        authorization(
                            hid,
                            channel,
                            config,
                            &mut child,
                            &mut stdin,
                            &mut stdout,
                            &mut event_buf,
                        )?;
                    }
                    return Ok(i);
                }
                _ => unreachable!(),
            }
        } else {
            std::thread::sleep(Duration::from_millis(200));
        }
    }
}

/// Returns Ok() for successfull authorization
fn authorization(
    hid: &mut Ctaphid,
    channel: Channel,
    config: &Config,
    child: &mut SystemdChild,
    stdin: &mut ChildStdin,
    stdout: &mut ChildStdout,
    event_buf: &mut Vec<u8>,
) -> anyhow::Result<()> {
    let mut auth = &config.auth;
    loop {
        let auth_outcome = match auth {
            Auth::PASS => authorization_pass(hid, channel, config, child, stdin, stdout, event_buf),
            Auth::FPRINT => {
                authorization_fprint(hid, channel, config, child, stdin, stdout, event_buf)
            }
            Auth::PAM => authorization_pam(hid, channel, config, child, stdin, stdout, event_buf),
        };

        match auth_outcome? {
            AuthorizationOutcome::Authorized => {
                return Ok(());
            }
            AuthorizationOutcome::UnAuthorized => {
                anyhow::bail!(CtapStatus::UvBlocked);
            }
            AuthorizationOutcome::FallbackToPassword(reason) => {
                auth = &Auth::PASS;
                send_command(stdin, ServiceMessage::FallbackToPassword(reason))?;
            }
        }
    }
}

fn send_command(stdin: &mut ChildStdin, command: ServiceMessage) -> anyhow::Result<()> {
    stdin
        .write_all(CborVec::from_serializable(command, size_of::<ServiceMessage>()).as_ref())
        .map_err(anyhow::Error::from)
}

/*
* Technically, I can check this initially before setting the config and fallback before ever reaching fprint, but the hardware could’ve just failed since the app session is gonna be long.
* idk, it just doesn’t feel right to check those initially when it could’ve clearly changed later over a long duration.
*/

fn authorization_fprint(
    hid: &mut Ctaphid,
    channel: Channel,
    config: &Config,
    child: &mut SystemdChild,
    stdin: &mut ChildStdin,
    _stdout: &mut ChildStdout,
    _event_buf: &mut Vec<u8>,
) -> anyhow::Result<AuthorizationOutcome> {
    let Ok(connection) = Connection::session() else {
        return Ok(AuthorizationOutcome::FallbackToPassword(
            FallbackToPasswordReason::FingerprintDeviceUnavailable,
        ));
    };
    let Ok(fprint_manager) = FprintManagerProxyBlocking::new(&connection) else {
        return Ok(AuthorizationOutcome::FallbackToPassword(
            FallbackToPasswordReason::FingerprintDeviceUnavailable,
        ));
    };

    let Ok(device_path) = fprint_manager.get_default_device() else {
        return Ok(AuthorizationOutcome::FallbackToPassword(
            FallbackToPasswordReason::FingerprintDeviceUnavailable,
        ));
    };

    let Ok(fprint_device) = FprintDeviceProxyBlocking::new(&connection, device_path) else {
        return Ok(AuthorizationOutcome::FallbackToPassword(
            FallbackToPasswordReason::FingerprintDeviceUnavailable,
        ));
    };

    let username = get_username_from_uid(config.gui_uid).ok_or(CtapStatus::OperationDenied)?;
    let Ok(enrolled) = fprint_device.list_enrolled_fingers(&username) else {
        info!("[Fingureprint] No enrolled key found");
        return Ok(AuthorizationOutcome::FallbackToPassword(
            FallbackToPasswordReason::FingerprintDeviceUnavailable,
        ));
    };

    if enrolled.is_empty() {
        info!("[Fingureprint] No enrolled key found");
        return Ok(AuthorizationOutcome::FallbackToPassword(
            FallbackToPasswordReason::FingerprintDeviceUnavailable,
        ));
    }

    debug!("[Fingureprint] Claming device...");
    if fprint_device.claim(&username).is_err() {
        return Ok(AuthorizationOutcome::FallbackToPassword(
            FallbackToPasswordReason::FingerprintDeviceUnavailable,
        ));
    };

    fprint_device.verify_start("")?;

    let mut status_stream = fprint_device.receive_verify_status()?;

    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        while let Some(signal) = status_stream.next() {
            if let Ok(args) = signal.args() {
                if tx.send(args.result).is_err() {
                    break;
                }
            }
        }
    });

    const MAX_ATTEMPTS: usize = 3;
    let mut attempts = 0;

    loop {
        if let Ok(status) = rx.try_recv() {
            match status.as_str() {
                "verify-match" => {
                    let _ = fprint_device.verify_stop();
                    let _ = fprint_device.release();
                    debug!("[Fingureprint] Releasing device...");
                    return Ok(AuthorizationOutcome::Authorized);
                }
                "verify-no-match" => {
                    attempts = attempts + 1;

                    if attempts >= MAX_ATTEMPTS {
                        let _ = fprint_device.verify_stop();
                        let _ = fprint_device.release();
                        debug!("[Fingureprint] Releasing device...");
                        return Ok(AuthorizationOutcome::UnAuthorized);
                    }

                    send_command(stdin, ServiceMessage::Retry)?;
                }
                "verify-unknown-error" => {
                    let _ = fprint_device.verify_stop();
                    let _ = fprint_device.release();
                    debug!("[Fingureprint] Releasing device...");
                    return Ok(AuthorizationOutcome::FallbackToPassword(
                        FallbackToPasswordReason::FingerprintDeviceUnavailable,
                    ));
                }
                _ => send_command(stdin, ServiceMessage::Retry)?,
            };
        };

        if child
            .inner
            .try_wait()
            .context("failed to poll UI process")?
            .is_some()
        {
            let _ = fprint_device.verify_stop();
            let _ = fprint_device.release();
            anyhow::bail!(CtapStatus::OperationDenied);
        }

        if try_recv_cancel(hid, channel)?.is_some() {
            let _ = fprint_device.verify_stop();
            let _ = fprint_device.release();
            let _ = child.kill();
            let _ = child.inner.wait();
            anyhow::bail!(CtapStatus::KeepaliveCancel);
        };

        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}

fn authorization_pam(
    hid: &mut Ctaphid,
    channel: Channel,
    _config: &Config,
    child: &mut SystemdChild,
    stdin: &mut ChildStdin,
    stdout: &mut ChildStdout,
    event_buf: &mut Vec<u8>,
) -> anyhow::Result<AuthorizationOutcome> {
    // let username = get_username_from_uid(config.gui_uid).ok_or(CtapStatus::OperationDenied)?;

    let (question_tx, question_rx) = mpsc::channel();
    let (answer_tx, answer_rx) = mpsc::channel();
    let (pam_result_tx, pam_result_rx) = mpsc::channel();

    let conv = InteractiveConversation {
        answer_rx: answer_rx,
        question_tx: question_tx,
    };

    let Ok(mut client) = pam::Client::with_conversation("passkeyd", conv) else {
        return Ok(AuthorizationOutcome::FallbackToPassword(
            FallbackToPasswordReason::FingerprintDeviceUnavailable,
        ));
    };

    std::thread::spawn(move || {
        let _ = pam_result_tx.send(client.authenticate());
    });

    loop {
        if let Ok(question) = question_rx.try_recv() {
            send_command(stdin, ServiceMessage::PAMQuestion(question))?;
        }

        if let Some(UIMessage::Password(ans)) =
            try_ui_message(hid, channel, child, stdout, event_buf)?
        {
            answer_tx
                .send(ans)
                .map_err(|_| anyhow::anyhow!("Unexpectedly, PAM authentication thread died"))?;
        }

        match pam_result_rx.try_recv() {
            Ok(Ok(())) => return Ok(AuthorizationOutcome::Authorized),
            Ok(Err(_pam_err)) => return Ok(AuthorizationOutcome::UnAuthorized),

            Err(TryRecvError::Disconnected) => {
                return Err(anyhow::anyhow!(
                    "Unexpectedly, PAM authentication thread died"
                ));
            }
            Err(TryRecvError::Empty) => (),
        }

        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}

fn authorization_pass(
    hid: &mut Ctaphid,
    channel: Channel,
    config: &Config,
    child: &mut SystemdChild,
    stdin: &mut ChildStdin,
    stdout: &mut ChildStdout,
    event_buf: &mut Vec<u8>,
) -> anyhow::Result<AuthorizationOutcome> {
    let username = get_username_from_uid(config.gui_uid).ok_or(CtapStatus::OperationDenied)?;
    const MAX_ATTEMPTS: usize = 3;
    let mut attempts = 0;

    loop {
        if let Some(UIMessage::Password(pass)) =
            try_ui_message(hid, channel, child, stdout, event_buf)?
        {
            if verify_password(&username, &pass)? {
                return Ok(AuthorizationOutcome::Authorized);
            }
            attempts += 1;
            if attempts >= MAX_ATTEMPTS {
                return Ok(AuthorizationOutcome::UnAuthorized);
            }
            send_command(stdin, ServiceMessage::Retry)?;
        };
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}

/// If `Some(())` is retuned, cancel request is received
/// None is returned, no cancel request
fn try_recv_cancel(hid: &mut Ctaphid, channel: Channel) -> anyhow::Result<Option<()>> {
    if !hid.hid.is_readable() {
        return Ok(None);
    }
    // get_webauthn is responsible for readable states
    // is_readble just read the status provided by get_webauthn
    // so, get_webauth must be called
    match hid.get_webauthn()? {
        Some((incoming_channel, _)) => {
            // Well, could handle this too by passing it to the dispatcher.
            // But I don't think it would be that useful. I mean, why the hell are you even invoking
            // auth twice(you need to invoke in one tab and then switch to another tab to invoke another)?
            // If you're exercising free will, that's a different case.
            // otherwise, GET YOUR SELF A BRAIN CHECK

            error!("sent busy to channel {incoming_channel:?} caz currently processing {channel}");

            anyhow::bail!(TransportError {
                channel: incoming_channel,
                err: DeviceError::ChannelBusy
            });
        }
        None if hid.is_cancelled(channel) => Ok(Some(())),
        _ => Ok(None),
    }
}

fn try_ui_message(
    hid: &mut Ctaphid,
    channel: Channel,
    child: &mut SystemdChild,
    stdout: &mut ChildStdout,
    event_buf: &mut Vec<u8>,
) -> anyhow::Result<Option<UIMessage>> {
    if try_recv_cancel(hid, channel)?.is_some() {
        let _ = child.kill();
        let _ = child.inner.wait();
        anyhow::bail!(CtapStatus::KeepaliveCancel);
    };

    if let Some(_) = child
        .inner
        .try_wait()
        .context("failed to poll UI process")?
    {
        anyhow::bail!(CtapStatus::OperationDenied);
    }

    if stdout.is_readable() {
        let mut temp_buff = [0; 512];
        loop {
            match cbor_deserialize(event_buf.as_slice()) {
                Ok(res) => return Ok(res),
                Err(_) => {
                    // If it failed probably because don't got enough bytes read more from stdout.
                    let n = stdout.read(&mut temp_buff)?;
                    if n == 0 {
                        anyhow::bail!("Child stdout closed unexpectedly");
                    }
                    event_buf.extend_from_slice(&temp_buff[..n]);
                }
            }
        }
    }
    Ok(None)
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
