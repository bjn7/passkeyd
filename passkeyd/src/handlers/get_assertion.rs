use crate::{
    cerds,
    ctaphid::{CtapStatus, ctaphid::Ctaphid},
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
) -> anyhow::Result<()> {
    let response = cerds::get::get(config, req);
    let mut report = [0u8; size_of::<get_assertion::Response>() + 1]; //approx size.

    match response {
        Ok(res) => {
            let size = cbor_serialize_to(&res, &mut report[1..])?;
            let final_cbor = &mut report[..size + 1];
            hid.send_response(channel, Command::Cbor, final_cbor)?;
            debug!("Acknowledged ctab instruction \'GetAssertion\'");
        }
        Err(e) => {
            if let Some(err) = e.downcast_ref::<CtapStatus>() {
                report[0] = *err as u8;
            } else {
                report[0] = CtapStatus::Other as u8;
            }
            hid.send_64response(channel, Command::Cbor, &report[..1])?;
        }
    };

    Ok(())
}
