use crate::{
    cerds::{self, get::GetOutcome},
    ctaphid::{CtapStatus, TransportError, ctaphid::Ctaphid},
};
use ctap_types::{ctap2::get_assertion, serde::cbor_serialize_to};
use ctaphid_types::{Channel, Command};
use log::debug;
use passkeyd_abi::config::Config;

pub fn handle(
    hid: &mut Ctaphid,
    config: &Config,
    channel: Channel,
    req: get_assertion::Request<'_>,
    raw_cbor: &[u8],
) -> anyhow::Result<()> {
    let response = cerds::get::get(hid, channel, config, req, raw_cbor);
    let mut report = [0u8; size_of::<get_assertion::Response>() + 1]; //approx size.

    match response {
        Ok(GetOutcome::Local(res)) => {
            let size = cbor_serialize_to(&res, &mut report[1..])?;
            let final_cbor = &mut report[..size + 1];
            hid.send_response(channel, Command::Cbor, final_cbor)?;
            debug!("Acknowledged CTAP instruction 'GetAssertion'");
        }
        Ok(GetOutcome::External(phone_cbor)) => {
            let final_cbor = crate::cable::format_ctap_cbor_response(&phone_cbor);
            hid.send_response(channel, Command::Cbor, &final_cbor)?;
            log::info!("Acknowledged CTAP instruction 'GetAssertion' via caBLE hybrid transport");
        }
        Err(e) => {
            if let Some(err) = e.downcast_ref::<CtapStatus>() {
                report[0] = *err as u8;
                hid.send_64response(channel, Command::Cbor, &report[0..1])?;
            } else if let Some(err) = e.downcast_ref::<TransportError>() {
                hid.send_portocal_error(err.channel, err.err)?;
            } else {
                report[0] = CtapStatus::Other as u8;
                hid.send_64response(channel, Command::Cbor, &report[0..1])?;
            }
        }
    };

    Ok(())
}
