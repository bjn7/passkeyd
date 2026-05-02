use ctap_types::serde::cbor_serialize_to;
use ctaphid_types::{Channel, Command};
use log::debug;
use passkeyd_abi::config::Config;

use crate::{
    cerds,
    ctaphid::{CtapStatus, ctaphid::Ctaphid},
};

pub fn handle(
    hid: &mut Ctaphid,
    config: &Config,
    channel: Channel,
    req: ctap_types::ctap2::make_credential::Request<'_>,
) -> anyhow::Result<()> {
    let response = cerds::make::make(config, req);
    let mut report = [0u8; size_of::<ctap_types::ctap2::make_credential::Response>() + 1];

    match response {
        Ok(res) => {
            let size = cbor_serialize_to(&res, &mut report[1..])?;
            let final_cbor = &mut report[..size + 1];
            hid.send_response(channel, Command::Cbor, final_cbor)?;
            debug!("Acknowledged ctab instruction \'MakeCredential\'");
        }
        Err(e) => {
            if let Some(err) = e.downcast_ref::<CtapStatus>() {
                report[0] = *err as u8;
            } else {
                report[0] = CtapStatus::Other as u8;
            }
            hid.send_64response(channel, Command::Cbor, &report[0..1])?;
        }
    };
    
    Ok(())
}
