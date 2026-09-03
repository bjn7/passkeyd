use std::process::{ChildStdout, ExitStatus};

use anyhow::Context;
use ctaphid_types::{Channel, DeviceError};
use log::{error, info};
use passkeyd_abi::utils::SystemdChild;

use crate::ctaphid::{CtapStatus, TransportError, ctaphid::Ctaphid};

unsafe extern "C" {
    fn hid_init() -> i32;

    fn hid_exit() -> i32;

    fn hid_enumerate(vendor_id: u16, product_id: u16) -> *mut HidDeviceInfo;

    fn hid_free_enumeration(devs: *mut HidDeviceInfo);
}

#[repr(C)]
struct HidDeviceInfo {
    path: *mut std::ffi::c_char,
    vendor_id: u16,
    product_id: u16,
    serial_number: *mut u16,
    release_number: u16,
    manufacturer_string: *mut u16,
    product_string: *mut u16,
    usage_page: u16,
    usage: u16,
    interface_number: i32,
    next: *mut HidDeviceInfo,
}

// whether the device has any other security keys.
pub fn has_another_fido_device() -> bool {
    unsafe {
        if hid_init() != 0 {
            return false;
        }

        let devices = hid_enumerate(0, 0);

        if devices.is_null() {
            hid_exit();
            return false;
        }

        let mut device = devices;
        let mut device_count: usize = 0;

        while !device.is_null() {
            device_count += ((*device).usage_page == 0xF1D0 && (*device).usage == 0x01) as usize;

            if device_count > 1 {
                break;
            }

            device = (*device).next;
        }

        hid_free_enumeration(devices);
        hid_exit();

        device_count > 1
    }
}

/* The basic idea is:
// 	Spawn a UI
// 	Poll if the UI has exited
// 	If it exited with 0, i.e. send back to Chrome to use this for the passkey
// 	If it exited with 1, i.e. send back to Chrome to not use this one

// 	Poll if the UI hasn't exited
// 	If HID has some read events, call WebAuthn, which will also handle the cancel command
// 		If there was a Some response from WebAuthn, then this event isn't a cancel event
// 			It will be handled normally by the dispatcher
// 		If there was a None response from WebAuthn, then this is probably a cancel event
// 			Check it using is_cancelled(channel)
// 			If it is cancelled, kill the UI and exit the loop

// 	If HID has no read events, go back to polling for UI exit
*/

pub struct UIResponse {
    pub exit_status: ExitStatus,
    pub stdout: ChildStdout,
}

pub fn cancellable_ui(
    hid: &mut Ctaphid,
    channel: Channel,
    mut child: SystemdChild,
) -> anyhow::Result<UIResponse> {
    loop {
        if hid.hid.is_readable() {
            // get_webauthn is responsible for readable states
            // is_readble just read the status provided by get_webauthn
            // so, get_webauth must be called
            match hid.get_webauthn()? {
                Some((incoming_channel, _)) => {
                    // Well, could handle this too by passing it to the dispatcher.
                    // But I don't think it would be that useful. I mean, why the hell are you even invoking
                    // auth twice(you need to invoke in one tab and then switch to another tab to invoke another)?
                    // If you're exercising free will, that's a different case.
                    // otherwise, GET YOUR SELF A BRAIN CHECK

                    let _ = child.kill();
                    let _ = child.inner.wait();
                    info!("Killed User Interface");

                    error!(
                        "sent busy to channel {incoming_channel:?} caz currently processing {channel}"
                    );

                    anyhow::bail!(TransportError {
                        channel: incoming_channel,
                        err: DeviceError::ChannelBusy
                    });
                }
                None if hid.is_cancelled(channel) => {
                    let _ = child.kill();
                    let _ = child.inner.wait();
                    info!("Killed User Interface");
                    // hid.send_cbor_status(channel, CtapStatus::KeepaliveCancel)?;
                    anyhow::bail!(CtapStatus::KeepaliveCancel);
                }
                _ => (),
            }
        }

        if let Some(status) = child
            .inner
            .try_wait()
            .context("failed to poll UI process")?
        {
            return Ok(UIResponse {
                exit_status: status,
                stdout: child.inner.stdout.take().unwrap(), //stdout will always exist as, the child was created with its stdout piped
            });
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}
