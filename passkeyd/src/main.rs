use log::{debug, error};
use passkeyd_abi::config;

mod cerds;
mod cryptography;
mod ctaphid;
mod handlers;
mod utils;

fn main() -> anyhow::Result<()> {
    let config = config::Config::initialize()?;
    env_logger::init();
    passkeyd_locale::init_translations();

    let mut hid = ctaphid::ctaphid::Ctaphid::new();
    debug!("Passkeyd started. Waiting for HID packets...");

    loop {
        if let Some((channel, cbor)) = hid.get_webauthn()? {
            if let Err(e) = handlers::dispatch(&mut hid, &config, channel, &cbor) {
                error!("Error handling CTAP request: {e}");
            }
            debug!("Transaction completed on channel {channel}");
        }
    }
}
