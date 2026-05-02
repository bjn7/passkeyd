use cosey::EcdhEsHkdf256PublicKey;
use ctap_types::ctap2::client_pin::{self, PinV1Subcommand};
use ctaphid_types::Channel;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use passkeyd_abi::config::Config;

use crate::ctaphid::{CtapStatus, ctaphid::Ctaphid};

pub fn handle(
    hid: &mut Ctaphid,
    _config: &Config,
    channel: Channel,
    req: client_pin::Request<'_>,
) -> anyhow::Result<()> {
    // THIS IS CURRENTLY "TODO" AND UNREACHABLE
    let mut res = client_pin::Response::default();
    match req.sub_command {
        PinV1Subcommand::GetRetries => {
            res.retries = Some(3);
            res.power_cycle_state = Some(false);

            hid.send_cbor(channel, res)?;
        }

        PinV1Subcommand::GetUVRetries => {
            res.uv_retries = Some(3);
        }

        PinV1Subcommand::GetKeyAgreement => {
            let public_key = hid.ephemeral_secret.public_key();
            let encoded = public_key.to_encoded_point(false);
            let x = encoded.x().expect("X is missing");
            let y = encoded.y().expect("Y is missing");

            let x_bytes =
                ctap_types::Bytes::<32>::from_slice(x.as_slice()).expect("X must be 32 bytes");
            let y_bytes =
                ctap_types::Bytes::<32>::from_slice(y.as_slice()).expect("Y must be 32 bytes");

            res.key_agreement = Some(EcdhEsHkdf256PublicKey {
                x: x_bytes,
                y: y_bytes,
            });
        }

        PinV1Subcommand::ChangePin | PinV1Subcommand::SetPin => {
            hid.send_cbor_status(channel, CtapStatus::OperationDenied)?;
        }
        PinV1Subcommand::GetPinToken => {
            todo!("HERE GET PIN TOKEN FIRED");
        }
        PinV1Subcommand::GetPinUvAuthTokenUsingPinWithPermissions => todo!(),
        PinV1Subcommand::GetPinUvAuthTokenUsingUvWithPermissions => todo!(),
        _ => todo!(),
    }
    todo!()
}
