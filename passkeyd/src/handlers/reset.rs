use crate::ctaphid::ctaphid::Ctaphid;
use ctaphid_types::Channel;
use log::error;
use passkeyd_abi::config::Config;

pub fn handle(_hid: &mut Ctaphid, _config: &Config, _channel: Channel) -> anyhow::Result<()> {
    error!("Reset is not yet supported, you may manually delete the database folder");
    Ok(())
}
