use ctaphid_types::{Channel, Command};
use passkeyd_abi::{
    config::Config,
    utils::{PresenceUI, UI, spawn_ui},
};

use crate::{
    ctaphid::{CtapStatus, TransportError, ctaphid::Ctaphid},
    utils::{UIResponse, cancellable_ui},
};

pub fn handle(hid: &mut Ctaphid, config: &Config, channel: Channel) -> anyhow::Result<()> {
    let ui_response = cancellable_ui(
        hid,
        channel,
        spawn_ui(
            config,
            UI::KeySelection,
            PresenceUI {
                // again, why is this thing borrowed? well, whatever
                title: &passkeyd_locale::translate!("passkeyd.cerds.make.presence_ui.title"),
                description: &passkeyd_locale::translate!(
                    "passkeyd.cerds.make.presence_ui.description"
                ),
                button: &passkeyd_locale::translate!("passkeyd.cerds.make.presence_ui.button"),
            },
        ),
    );

    match ui_response {
        Ok(UIResponse { exit_status, .. }) => {
            if exit_status.success() {
                hid.send_cbor_status(channel, CtapStatus::Ok)?;
            } else {
                hid.send_cbor_status(channel, CtapStatus::KeepaliveCancel)?;
            }
        }
        Err(e) => {
            if let Some(err) = e.downcast_ref::<CtapStatus>() {
                hid.send_64response(channel, Command::Cbor, [*err as u8])?;
            } else if let Some(err) = e.downcast_ref::<TransportError>() {
                hid.send_portocal_error(err.channel, err.err)?;
            } else {
                hid.send_cbor_status(channel, CtapStatus::Other)?;
                // hid.send_64response(channel, Command::Cbor, [CtapStatus::])?;
            }
        }
    };

    Ok(())
}
