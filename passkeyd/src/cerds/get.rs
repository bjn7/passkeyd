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

pub enum GetOutcome {
    Local(Response),
    External(Vec<u8>),
}

pub fn get(
    hid: &mut Ctaphid,
    channel: Channel,
    config: &Config,
    req: Request,
    raw_cbor: &[u8],
) -> anyhow::Result<GetOutcome> {
    let (rp_entity, mut passkeys) = load_passkeys(&req)?;
    let action = authorization_action(has_another_fido_device(), config.no_pass, passkeys.len());
    let authorized_index = match authorize(hid, channel, config, &rp_entity, &passkeys, action) {
        Ok(idx) => idx,
        Err(e) => {
            if let Some(ctap_err) = e.downcast_ref::<CtapStatus>() {
                if *ctap_err == CtapStatus::NoCredentials && config.allow_external_keys {
                    info!("No local credentials found; ALLOW_EXTERNAL_KEYS enabled, starting caBLE hybrid transport...");
                    let cable_res = perform_cable_assertion(hid, channel, raw_cbor)?;
                    return Ok(GetOutcome::External(cable_res));
                }
            }
            return Err(e);
        }
    };
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

    Ok(GetOutcome::Local(response))
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

#[derive(Debug, PartialEq, Eq)]
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
        // no other key and no credentials either,
        // send the no cerds directly. the password
        // does not matter here, there is nothing to
        // unlock in the first place.
        (false, _, 0) => AuthorizationAction::NoCredentials,

        // no other key, no password
        // and but one credential
        // skip ui, send the cerds directly
        (false, true, 1) => AuthorizationAction::UseOnlyPasskey,

        // another key, but either no or single cerd
        // the user intent is probably to use
        // either security key or use passkeyd
        // so, presence to reduce ambiguity.
        // with no cerd of ours the password does not
        // matter either, presence still lets the user
        // reach for the external key.
        (true, _, 0) => AuthorizationAction::Presence,
        (true, true, 1) => AuthorizationAction::Presence,

        // If no another key, no password, there are more than 1 cerds, selection is obviously needed.
        // If another key, has password, arbitrary cerds, selection will handle it.
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
    if passkeys.is_empty() {
        anyhow::bail!(CtapStatus::NoCredentials);
    }

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
    let mut stdin = child.inner.stdin.take();
    let mut stdout = child
        .inner
        .stdout
        .take()
        .context("failed to get UI stdout")?;
    let mut event_buf = Vec::new();

    loop {
        if let Some(event) = try_ui_message(hid, channel, &mut child, &mut stdout, &mut event_buf)?
        {
            match event {
                UIMessage::SelectionDoneMaybeStartAuth(i) => {
                    if !config.no_pass {
                        let stdin = stdin.as_mut().context("child stdin unavailable")?;
                        authorization(
                            hid,
                            channel,
                            config,
                            &mut child,
                            stdin,
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
    while hid.hid.is_readable() {
        match hid.get_webauthn()? {
            Some((incoming_channel, _)) => {
                error!("sent busy to channel {incoming_channel:?} caz currently processing {channel}");
                anyhow::bail!(TransportError {
                    channel: incoming_channel,
                    err: DeviceError::ChannelBusy
                });
            }
            None if hid.is_cancelled(channel) => return Ok(Some(())),
            _ => (),
        }
    }
    if hid.is_cancelled(channel) {
        Ok(Some(()))
    } else {
        Ok(None)
    }
}

fn perform_cable_assertion(
    hid: &mut Ctaphid,
    channel: Channel,
    raw_cbor: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let (tx, rx) = mpsc::channel();
    let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel();
    let raw_cbor_vec = raw_cbor.to_vec();

    let cable_thread = std::thread::spawn(move || {
        let res = crate::cable::perform_hybrid_assertion(&raw_cbor_vec, cancel_rx);
        let _ = tx.send(res);
    });

    let mut last_keepalive = std::time::Instant::now();

    loop {
        if let Some(()) = try_recv_cancel(hid, channel)? {
            info!("Cancellation received from host; terminating caBLE session");
            let _ = cancel_tx.send(());
            let _ = cable_thread.join();
            hid.clear_cancelled(channel);
            anyhow::bail!(CtapStatus::KeepaliveCancel);
        }

        // FIDO CTAPHID spec: Send periodic keepalive (0x02 = STATUS_UPNEEDED) every 100ms
        // so the host/browser knows the authenticator is waiting for user presence and keeps
        // its HID read loop responsive to cancellation events.
        if last_keepalive.elapsed() >= Duration::from_millis(100) {
            let _ = hid.send_64response(channel, ctaphid_types::Command::KeepAlive, [0x02]);
            last_keepalive = std::time::Instant::now();
        }

        match rx.try_recv() {
            Ok(res) => {
                let _ = cable_thread.join();
                return res;
            }
            Err(TryRecvError::Empty) => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(TryRecvError::Disconnected) => {
                let _ = cable_thread.join();
                anyhow::bail!("caBLE assertion thread terminated unexpectedly");
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_authorization_action_zero_credentials() {
        // When there are no credentials stored, it should always return NoCredentials,
        // allowing caBLE hybrid transport or another authenticator to handle the request.
        assert_eq!(
            authorization_action(false, false, 0),
            AuthorizationAction::NoCredentials
        );
        assert_eq!(
            authorization_action(false, true, 0),
            AuthorizationAction::NoCredentials
        );
        assert_eq!(
            authorization_action(true, false, 0),
            AuthorizationAction::Presence
        );
        assert_eq!(
            authorization_action(true, true, 0),
            AuthorizationAction::Presence
        );
    }

    #[test]
    fn test_authorization_action_single_credential() {
        // No other key, password disabled: skip UI directly
        assert_eq!(
            authorization_action(false, true, 1),
            AuthorizationAction::UseOnlyPasskey
        );
        // Another key present, password disabled: user presence check
        assert_eq!(
            authorization_action(true, true, 1),
            AuthorizationAction::Presence
        );
        // Password enabled: selection & authentication required
        assert_eq!(
            authorization_action(false, false, 1),
            AuthorizationAction::Selection
        );
        assert_eq!(
            authorization_action(true, false, 1),
            AuthorizationAction::Selection
        );
    }

    #[test]
    fn test_authorization_action_multiple_credentials() {
        // Multiple credentials always require selection
        assert_eq!(
            authorization_action(false, false, 2),
            AuthorizationAction::Selection
        );
        assert_eq!(
            authorization_action(false, true, 2),
            AuthorizationAction::Selection
        );
        assert_eq!(
            authorization_action(true, false, 2),
            AuthorizationAction::Selection
        );
        assert_eq!(
            authorization_action(true, true, 2),
            AuthorizationAction::Selection
        );
    }

    #[test]
    fn test_get_outcome_variants() {
        let external = GetOutcome::External(vec![0x01, 0x02]);
        match external {
            GetOutcome::External(bytes) => assert_eq!(bytes, vec![0x01, 0x02]),
            _ => panic!("Expected GetOutcome::External"),
        }
    }
}

