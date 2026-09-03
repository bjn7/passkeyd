use ctap_types::ctap2::Request;
use ctaphid_types::Channel;
use log::debug;
use passkeyd_abi::config::Config;

use crate::ctaphid::ctaphid::Ctaphid;

pub mod client_pin;
pub mod get_assertion;
pub mod get_info;
pub mod get_next_assertion;
pub mod make_credential;
pub mod reset;
pub mod selection;

pub fn dispatch(
    hid: &mut Ctaphid,
    config: &Config,
    channel: Channel,
    cbor: &[u8],
) -> anyhow::Result<()> {
    let request = Request::deserialize(cbor).unwrap();
    let cmd_name = get_request_name(&request);

    debug!(
        "Received CTAP instruction: '{}' on channel {}",
        cmd_name, channel
    );

    let result = match Request::deserialize(cbor).unwrap() {
        Request::GetInfo => get_info::handle(hid, config, channel),
        Request::MakeCredential(req) => make_credential::handle(hid, config, channel, req),
        Request::GetAssertion(req) => get_assertion::handle(hid, config, channel, req),
        Request::GetNextAssertion => get_next_assertion::handle(hid, config, channel),
        Request::ClientPin(req) => client_pin::handle(hid, config, channel, req), // todo!()
        Request::Reset => reset::handle(hid, config, channel),
        Request::Selection => selection::handle(hid, config, channel),
        Request::CredentialManagement(_) => todo!(),
        Request::LargeBlobs(_) => todo!(),
        Request::Vendor(_) => unreachable!(),
        _ => unreachable!("This command is not supported yet"),
    };

    if result.is_ok() {
        debug!("Acknowledged CTAP instruction: '{}'", cmd_name);
    }

    result
}

fn get_request_name(request: &Request) -> &'static str {
    match request {
        Request::GetInfo => "GetInfo",
        Request::MakeCredential(_) => "MakeCredential",
        Request::GetAssertion(_) => "GetAssertion",
        Request::GetNextAssertion => "GetNextAssertion",
        Request::ClientPin(_) => "ClientPin",
        Request::Reset => "Reset",
        Request::CredentialManagement(_) => "CredentialManagement",
        Request::Selection => "Selection",
        Request::LargeBlobs(_) => "LargeBlobs",
        Request::Vendor(_) => "Vendor",
        _ => "Unknown/Unsupported",
    }
}
