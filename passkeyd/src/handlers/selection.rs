use ctaphid_types::Channel;
use passkeyd_abi::config::Config;

use crate::ctaphid::{CtapStatus, ctaphid::Ctaphid};

pub fn handle(hid: &mut Ctaphid, _config: &Config, channel: Channel) -> anyhow::Result<()> {
    // Assuming the device uses only this s a  way of authenticator.
    // Todo!(): prompt to select this authenticator
    hid.send_cbor_status(channel, CtapStatus::Ok)?;

    Ok(())
}
