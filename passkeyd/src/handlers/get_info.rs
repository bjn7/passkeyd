use ctap_types::{ctap2::get_info, serde::cbor_serialize};
use ctaphid_types::{Channel, Command};
use passkeyd_abi::config::Config;

use crate::ctaphid::ctaphid::Ctaphid;

pub fn handle(hid: &mut Ctaphid, _config: &Config, channel: Channel) -> anyhow::Result<()> {
    let mut response = get_info::ResponseBuilder {
        versions: ctap_types::Vec::from_iter([get_info::Version::Fido2_0]),
        aaguid: ctap_types::Bytes::from_slice(&[0u8; 16]).unwrap(),
    }
    .build();

    let mut options = get_info::CtapOptions::default();
    options.client_pin = None; // PIN support
    options.cred_mgmt = None;
    options.large_blobs = None;
    options.pin_uv_auth_token = None;

    options.up = true; //up support
    options.uv = Some(true); //user verification
    options.rk = true;
    options.plat = Some(true);

    response.options = Some(options);
    // response.pin_protocols = Some(ctap_types::Vec::from_iter([1]));
    let mut serialized_data = [0u8; size_of::<get_info::Response>() + 1];
    let serialized_cbor = cbor_serialize(&response, &mut serialized_data[1..])?;
    let length = serialized_cbor.len();
    let final_cbor = &mut serialized_data[..length + 1];
    hid.send_64response(channel, Command::Cbor, final_cbor)?;
    Ok(())
}
