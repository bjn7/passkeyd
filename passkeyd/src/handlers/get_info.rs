use ctap_types::{ctap2::get_info, serde::cbor_serialize};
use ctaphid_types::{Channel, Command};
use passkeyd_abi::config::Config;

use crate::ctaphid::ctaphid::Ctaphid;

pub fn build_get_info_response() -> get_info::Response {
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
    response
}

pub fn handle(hid: &mut Ctaphid, _config: &Config, channel: Channel) -> anyhow::Result<()> {
    let response = build_get_info_response();

    let mut serialized_data = [0u8; size_of::<get_info::Response>() + 1];
    let serialized_cbor = cbor_serialize(&response, &mut serialized_data[1..])?;
    let length = serialized_cbor.len();
    let final_cbor = &mut serialized_data[..length + 1];
    hid.send_response(channel, Command::Cbor, final_cbor)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ctaphid_types::Message;

    #[test]
    fn test_get_info_manifest_contains_fido2_0() {
        let resp = build_get_info_response();
        assert!(resp.versions.contains(&get_info::Version::Fido2_0));
        assert_eq!(resp.options.as_ref().unwrap().rk, true);
        assert_eq!(resp.options.as_ref().unwrap().uv, Some(true));
    }

    #[test]
    fn test_get_info_fragmentation_across_packets() {
        let resp = build_get_info_response();
        let mut serialized_data = [0u8; size_of::<get_info::Response>() + 1];
        let serialized_cbor = cbor_serialize(&resp, &mut serialized_data[1..]).unwrap();
        let length = serialized_cbor.len();
        let final_cbor = &serialized_data[..length + 1];

        let message = Message {
            channel: Channel::from(1),
            command: Command::Cbor,
            data: final_cbor,
        };
        let fragments: Vec<_> = message.fragments(64).unwrap().collect();
        assert!(!fragments.is_empty(), "Must produce at least one CTAPHID packet");
        assert!(fragments.len() >= 1);
    }
}

