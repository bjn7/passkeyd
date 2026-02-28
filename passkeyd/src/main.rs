use crate::ctaphid::CtapStatus;
use ctap_types::ctap2::{Request, get_info};
use ctap_types::serde::{cbor_serialize, cbor_serialize_to};
use ctaphid_types::Command;
use log::{debug, error};
use passkeyd_share::config;

fn main() -> anyhow::Result<()> {
    let config = config::Config::initialize()?;
    let mut hid = ctaphid::ctaphid::Ctaphid::new();
    loop {
        if let Some((channel, cbor)) = hid.get_webauthn()? {
            match Request::deserialize(&cbor).unwrap() {
                Request::GetInfo => {
                    debug!("Received ctap instruction \'GetInfo\'");

                    let mut response = get_info::ResponseBuilder {
                        versions: ctap_types::Vec::from_iter([get_info::Version::Fido2_0]),
                        aaguid: ctap_types::Bytes::from_slice(&[0u8; 16]).unwrap(),
                    }
                    .build();

                    let mut options = get_info::CtapOptions::default();
                    options.client_pin = None;
                    options.cred_mgmt = None;
                    options.large_blobs = None;
                    options.pin_uv_auth_token = None;
                    options.up = true;
                    options.rk = true;
                    options.uv = Some(true);
                    options.plat = Some(true);
                    response.options = Some(options);
                    let mut serialized_data = [0u8; size_of::<get_info::Response>() + 1];
                    let serialized_cbor = cbor_serialize(&response, &mut serialized_data[1..])?;
                    let length = serialized_cbor.len();
                    let final_cbor = &mut serialized_data[..length + 1];
                    hid.send_64response(channel, Command::Cbor, final_cbor)?;
                    debug!("Acknowledged ctab instruction \'GetInfo\'");
                }
                Request::MakeCredential(req) => {
                    debug!("Received ctab instruction \'MakeCredential\'");
                    let response = cerds::make::make(&config, req);
                    let mut report =
                        [0u8; size_of::<ctap_types::ctap2::make_credential::Response>() + 1];

                    match response {
                        Ok(res) => {
                            let size = cbor_serialize_to(&res, &mut report[1..])?;
                            let final_cbor = &mut report[..size + 1];
                            hid.send_response(channel, Command::Cbor, final_cbor)?;
                            debug!("Acknowledged ctab instruction \'MakeCredential\'");
                        }
                        Err(e) => {
                            if let Some(err) = e.downcast_ref::<CtapStatus>() {
                                report[0] = *err as u8;
                            } else {
                                report[0] = CtapStatus::Other as u8;
                            }
                            hid.send_64response(channel, Command::Cbor, &report[0..1])?;
                        }
                    };
                }

                Request::GetAssertion(req) => {
                    debug!("Received ctab instruction \'GetAssertion\'");

                    let response = cerds::get::get(&config, req);
                    let mut report =
                        [0u8; size_of::<ctap_types::ctap2::make_credential::Response>() + 1];

                    match response {
                        Ok(res) => {
                            let size = cbor_serialize_to(&res, &mut report[1..])?;
                            let final_cbor = &mut report[..size + 1];
                            hid.send_response(channel, Command::Cbor, final_cbor)?;
                            debug!("Acknowledged ctab instruction \'GetAssertion\'");
                        }
                        Err(e) => {
                            if let Some(err) = e.downcast_ref::<CtapStatus>() {
                                report[0] = *err as u8;
                            } else {
                                report[0] = CtapStatus::Other as u8;
                            }
                            hid.send_64response(channel, Command::Cbor, &report[..1])?;
                        }
                    };
                }

                // https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-client-to-authenticator-protocol-v2.0-id-20180227.html#authenticatorGetAssertion
                // The "GetNextAssertion" command is only triggered when the authenticator does not support a display.
                // Since this authenticator supports a display, the "GetNextAssertion" command is unreachable.
                Request::GetNextAssertion => unreachable!(),
                Request::ClientPin(_) => todo!(), // will be bound to user's pam or something
                Request::Reset => {
                    error!(
                        "Reset is not yet supported, you may manually delete the database folder"
                    );
                    todo!()
                }
                Request::CredentialManagement(_) => todo!(),
                Request::Selection => {
                    // Assuming the device uses only this s a  way of authenticator.
                    // Todo!(): prompt to select this authenticator
                    hid.send_64response(channel, Command::Cbor, [CtapStatus::Ok as u8])?;
                }
                Request::LargeBlobs(_) => todo!(),
                Request::Vendor(_) => unreachable!(),
                _ => unreachable!("This command is not supported yet"),
            }
            debug!("Acknowledged Cbor");
        }
    }
}

mod cerds;
mod ctaphid;
mod tpm;
