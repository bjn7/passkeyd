use crate::ctaphid::ctaphid::Ctaphid;
use ctaphid_types::Channel;
use passkeyd_abi::config::Config;

pub fn handle(_hid: &mut Ctaphid, _config: &Config, _channel: Channel) -> anyhow::Result<()> {
    Ok(())
}
