mod vhid;
use vhid::{Bus, CreateParams};

pub use vhid::OutputEvent;
pub use vhid::UHIDDevice;

pub fn create_hid() -> Result<UHIDDevice<std::fs::File>, std::io::Error> {
    UHIDDevice::create(CreateParams {
        name: "passkey".into(),
        phys: "tpm-passkey".into(),
        uniq: "4f546e7a-897a-4ac0-bb69-e50ad255f1b0".into(),
        bus: Bus::USB,
        vendor: 0x1209, //OpenMoko
        product: 0x0001,
        version: 0x0001,
        country: 0,
        rd_data: fido_report_descriptor(),
    })
}

fn fido_report_descriptor() -> Vec<u8> {
    // Copied from: https://chromium.googlesource.com/chromiumos/platform2/+/master/u2fd/u2fhid.cc
    vec![
        0x06, 0xD0, 0xF1, /* Usage Page (FIDO Alliance), FIDO_USAGE_PAGE */
        0x09, 0x01, /* Usage (U2F HID Auth. Device) FIDO_USAGE_U2FHID */
        0xA1, 0x01, /* Collection (Application), HID_APPLICATION */
        0x09, 0x20, /*  Usage (Input Report Data), FIDO_USAGE_DATA_IN */
        0x15, 0x00, /*  Logical Minimum (0) */
        0x26, 0xFF, 0x00, /*  Logical Maximum (255) */
        0x75, 0x08, /*  Report Size (8) */
        0x95, 0x40, /*  Report Count (64), HID_INPUT_REPORT_BYTES */
        0x81, 0x02, /*  Input (Data, Var, Abs), Usage */
        0x09, 0x21, //   Usage (Output Report Data)
        0x15, 0x00, /*  Logical Minimum (0) */
        0x26, 0xFF, 0x00, /*  Logical Maximum (255) */
        0x75, 0x08, /*  Report Size (8) */
        0x95, 0x40, /*  Report Count (64), HID_OUTPUT_REPORT_BYTES */
        0x91, 0x02, /*  Output (Data, Var, Abs), Usage */
        0x09, 0x22, //   Usage (Feature Report Data)
        0x15, 0x00, //   Logical Minimum (0)
        0x26, 0xFF, 0x00, //   Logical Maximum (255)
        0x75, 0x08, //   Report Size (8 bits)
        0x95, 0x40, //   Report Count (64 bytes)
        0xB1, 0x02, //   Feature (Data, Var, Abs)
        0xC0, /* End Collection */
    ]
}
