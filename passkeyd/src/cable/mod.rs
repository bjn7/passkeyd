use anyhow::Result;
use log::info;
use qrcode::{render::unicode::Dense1x2, QrCode};
use webauthn_authenticator_rs::{
    cable::connect_cable_tunnel,
    error::WebauthnCError,
    types::{CableRequestType, CableState, EnrollSampleStatus},
    ui::UiCallback,
};
use crate::ctaphid::CtapStatus;

#[derive(Debug, Default, Clone)]
pub struct PasskeydCableUi;

impl UiCallback for PasskeydCableUi {
    fn request_pin(&self) -> Option<String> {
        None
    }

    fn request_touch(&self) {
        info!("caBLE request touch authenticator");
    }

    fn processing(&self) {
        info!("caBLE processing request...");
    }

    fn fingerprint_enrollment_feedback(
        &self,
        remaining_samples: u32,
        feedback: Option<EnrollSampleStatus>,
    ) {
        info!("caBLE fingerprint enrollment feedback: {remaining_samples} samples remaining, feedback: {feedback:?}");
    }

    fn cable_qr_code(&self, request_type: CableRequestType, url: String) {
        match request_type {
            CableRequestType::DiscoverableMakeCredential | CableRequestType::MakeCredential => {
                info!("Scan QR code with mobile device to register passkey via caBLE");
            }
            CableRequestType::GetAssertion => {
                info!("Scan QR code with mobile device to authenticate passkey via caBLE");
            }
        }

        if let Ok(qr) = QrCode::new(&url) {
            let code = qr
                .render::<Dense1x2>()
                .dark_color(Dense1x2::Light)
                .light_color(Dense1x2::Dark)
                .build();
            println!("\n{code}\n");
        }
        // Note: The raw pairing URL (containing the ephemeral qr_secret) is intentionally
        // omitted from stdout and log output to prevent secrets persisting in systemd journal.
    }

    fn dismiss_qr_code(&self) {
        info!("caBLE authenticator connected; dismissing QR code");
    }

    fn cable_status_update(&self, state: CableState) {
        info!("caBLE status: {state:?}");
    }
}

pub enum CableRequest<'a> {
    GetAssertion(&'a [u8]),
    MakeCredential(&'a [u8]),
}

/// Performs a synchronous hybrid transport (caBLE v2) passkey exchange.
/// Scopes its own multi-threaded Tokio runtime to avoid imposing async runtime constraints
/// on the caller or main daemon loop.
pub fn perform_hybrid_assertion(
    raw_ctap_request: &[u8],
    cancel_rx: tokio::sync::oneshot::Receiver<()>,
) -> Result<Vec<u8>> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;

    let res = rt.block_on(async move {
        tokio::select! {
            _ = cancel_rx => {
                info!("caBLE assertion cancelled by host");
                Err(anyhow::anyhow!(CtapStatus::KeepaliveCancel))
            }
            res = async {
                info!("Starting caBLE v2 hybrid assertion session...");
                let ui = PasskeydCableUi;
                let mut tunnel = connect_cable_tunnel(CableRequestType::GetAssertion, &ui).await
                    .map_err(|e| match e {
                        WebauthnCError::Cancelled | WebauthnCError::Closed => {
                            info!("caBLE session cancelled or closed before tunnel establishment");
                            anyhow::anyhow!(CtapStatus::KeepaliveCancel)
                        }
                        WebauthnCError::WebsocketError(msg) => {
                            info!("caBLE tunnel closed/error before establishment: {msg}");
                            anyhow::anyhow!(CtapStatus::KeepaliveCancel)
                        }
                        WebauthnCError::Ctap(ctap_err) => {
                            let status = CtapStatus::from(u8::from(ctap_err));
                            if status == CtapStatus::OperationDenied {
                                anyhow::anyhow!(CtapStatus::KeepaliveCancel)
                            } else {
                                anyhow::anyhow!(status)
                            }
                        }
                        other => anyhow::anyhow!("caBLE tunnel connection failed: {:?}", other),
                    })?;

                info!("caBLE tunnel connected! Transmitting CTAP assertion request ({} bytes)...", raw_ctap_request.len());
                let response = tunnel.transmit_cbor(raw_ctap_request, &ui).await
                    .map_err(|e| match e {
                        WebauthnCError::Cancelled | WebauthnCError::Closed => {
                            info!("caBLE assertion cancelled by user on mobile device");
                            anyhow::anyhow!(CtapStatus::KeepaliveCancel)
                        }
                        WebauthnCError::WebsocketError(msg) => {
                            info!("caBLE tunnel closed/error during assertion: {msg}");
                            anyhow::anyhow!(CtapStatus::KeepaliveCancel)
                        }
                        WebauthnCError::Ctap(ctap_err) => {
                            let status = CtapStatus::from(u8::from(ctap_err));
                            if status == CtapStatus::OperationDenied {
                                info!("caBLE mobile authenticator user consent denied");
                                anyhow::anyhow!(CtapStatus::KeepaliveCancel)
                            } else {
                                anyhow::anyhow!(status)
                            }
                        }
                        other => anyhow::anyhow!("caBLE CTAP assertion transmission failed: {:?}", other),
                    })?;

                info!("Received signed CTAP assertion response ({} bytes) from phone", response.len());
                Ok(response)
            } => res,
        }
    });

    rt.shutdown_background();
    res
}

pub fn perform_hybrid_make_credential(
    raw_ctap_request: &[u8],
    cancel_rx: tokio::sync::oneshot::Receiver<()>,
) -> Result<Vec<u8>> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;

    let res = rt.block_on(async move {
        tokio::select! {
            _ = cancel_rx => {
                info!("caBLE make credential cancelled by host");
                Err(anyhow::anyhow!(CtapStatus::KeepaliveCancel))
            }
            res = async {
                info!("Starting caBLE v2 hybrid make_credential session...");
                let ui = PasskeydCableUi;
                let mut tunnel = connect_cable_tunnel(CableRequestType::MakeCredential, &ui).await
                    .map_err(|e| match e {
                        WebauthnCError::Cancelled | WebauthnCError::Closed => {
                            info!("caBLE session cancelled or closed before tunnel establishment");
                            anyhow::anyhow!(CtapStatus::KeepaliveCancel)
                        }
                        WebauthnCError::WebsocketError(msg) => {
                            info!("caBLE tunnel closed/error before establishment: {msg}");
                            anyhow::anyhow!(CtapStatus::KeepaliveCancel)
                        }
                        WebauthnCError::Ctap(ctap_err) => {
                            let status = CtapStatus::from(u8::from(ctap_err));
                            if status == CtapStatus::OperationDenied {
                                anyhow::anyhow!(CtapStatus::KeepaliveCancel)
                            } else {
                                anyhow::anyhow!(status)
                            }
                        }
                        other => anyhow::anyhow!("caBLE tunnel connection failed: {:?}", other),
                    })?;

                info!("caBLE tunnel connected! Transmitting CTAP make_credential request ({} bytes)...", raw_ctap_request.len());
                let response = tunnel.transmit_cbor(raw_ctap_request, &ui).await
                    .map_err(|e| match e {
                        WebauthnCError::Cancelled | WebauthnCError::Closed => {
                            info!("caBLE make credential cancelled by user on mobile device");
                            anyhow::anyhow!(CtapStatus::KeepaliveCancel)
                        }
                        WebauthnCError::WebsocketError(msg) => {
                            info!("caBLE tunnel closed/error during make_credential: {msg}");
                            anyhow::anyhow!(CtapStatus::KeepaliveCancel)
                        }
                        WebauthnCError::Ctap(ctap_err) => {
                            let status = CtapStatus::from(u8::from(ctap_err));
                            if status == CtapStatus::OperationDenied {
                                info!("caBLE mobile authenticator user consent denied");
                                anyhow::anyhow!(CtapStatus::KeepaliveCancel)
                            } else {
                                anyhow::anyhow!(status)
                            }
                        }
                        other => anyhow::anyhow!("caBLE CTAP make_credential transmission failed: {:?}", other),
                    })?;

                info!("Received new CTAP credential response ({} bytes) from phone", response.len());
                Ok(response)
            } => res,
        }
    });

    rt.shutdown_background();
    res
}

pub fn format_ctap_cbor_response(payload: &[u8]) -> Vec<u8> {
    let mut response = Vec::with_capacity(payload.len() + 1);
    response.push(0x00); // Prepend CTAP2_OK status byte
    response.extend_from_slice(payload);
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_ctap_cbor_response_prepends_status() {
        let dummy_cbor = [0xa1, 0x01, 0x02];
        let framed = format_ctap_cbor_response(&dummy_cbor);
        assert_eq!(framed.len(), dummy_cbor.len() + 1);
        assert_eq!(framed[0], 0x00); // CTAP2_OK
        assert_eq!(&framed[1..], &dummy_cbor);
    }

    #[test]
    fn test_format_ctap_cbor_response_empty_payload() {
        let empty: [u8; 0] = [];
        let framed = format_ctap_cbor_response(&empty);
        assert_eq!(framed.len(), 1);
        assert_eq!(framed[0], 0x00);
    }

    #[test]
    fn test_scoped_tokio_runtime_lifecycle() {
        for i in 0..3 {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("Failed to build scoped Tokio runtime");

            let result = rt.block_on(async move {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                i * 10
            });

            assert_eq!(result, i * 10);
        }
    }

    #[test]
    fn test_perform_hybrid_assertion_cancellation() {
        let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel();
        let handle = std::thread::spawn(move || {
            perform_hybrid_assertion(&[0x01, 0x02], cancel_rx)
        });

        // Trigger cancellation immediately
        let _ = cancel_tx.send(());
        let res = handle.join().expect("Worker thread panicked");
        assert!(res.is_err());
        let err = res.unwrap_err();
        let ctap_status = err.downcast_ref::<CtapStatus>();
        assert_eq!(ctap_status, Some(&CtapStatus::KeepaliveCancel));
    }

    #[test]
    fn test_passkeyd_cable_ui_callbacks() {
        let ui = PasskeydCableUi;
        ui.cable_qr_code(CableRequestType::GetAssertion, "FIDO:/mock-qr-url".into());
        ui.cable_status_update(CableState::ConnectingToTunnelServer);
        ui.dismiss_qr_code();
        ui.processing();
        ui.request_touch();
        assert_eq!(ui.request_pin(), None);
    }

    #[test]
    fn test_ctap_error_mapping_downcast() {
        let op_denied: anyhow::Error = anyhow::anyhow!(CtapStatus::OperationDenied);
        assert_eq!(op_denied.downcast_ref::<CtapStatus>(), Some(&CtapStatus::OperationDenied));

        let no_creds: anyhow::Error = anyhow::anyhow!(CtapStatus::NoCredentials);
        assert_eq!(no_creds.downcast_ref::<CtapStatus>(), Some(&CtapStatus::NoCredentials));

        let uv_blocked: anyhow::Error = anyhow::anyhow!(CtapStatus::UvBlocked);
        assert_eq!(uv_blocked.downcast_ref::<CtapStatus>(), Some(&CtapStatus::UvBlocked));
    }
}
