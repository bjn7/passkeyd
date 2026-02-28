use anyhow::Ok;
use ctaphid_types::{
    Capabilities, Channel, Command, DeviceError, DeviceVersion, InitResponse, InitializationPacket,
    Message, Packet,
};
use std::{collections::HashMap, fs::File};

use crate::ctaphid::{
    hid::OutputEvent,
    utils::{collect_all_packet, device_err_into_bytes, generate_new_cid},
};

use log::{debug, error};

use super::hid;

type ReturnEvent = anyhow::Result<Option<(Channel, Vec<u8>)>>;
type HashableChannel = u32;

pub struct ChannelPayload {
    pub data: Vec<u8>,
    pub next_expected_sequence: u8,
}

pub struct Ctaphid {
    pub hid: hid::UHIDDevice<File>,
    // no need to free the channels, a average of 500 channels will be stored before getting wiped out by shutdown or restart.
    // todo!(): actually, once hit every 100 channels, drop 50 channels, so, it can maintain 100 channels.
    pub payload_stack: HashMap<HashableChannel, ChannelPayload>,
    // pub chancelled_channels: Vec<Channel>,
}

impl Ctaphid {
    pub fn new() -> Self {
        debug!("HID created!");

        Self {
            hid: hid::create_hid().expect("Failed to create HID, are you root?"),
            payload_stack: HashMap::with_capacity(10),
        }
    }

    pub fn get_webauthn(&mut self) -> ReturnEvent {
        let event = self.hid.read().expect("Failed to read events");
        self.event_handler(event)
    }

    pub fn event_handler(&mut self, event: OutputEvent) -> ReturnEvent {
        let hid::OutputEvent::Output { data: report_bytes } = event else {
            return Ok(None);
        };

        let raw_payload = &report_bytes[1..];
        let ctaphid_packet: Packet<Vec<u8>> = Packet::try_from(&raw_payload[..]).unwrap();
        match ctaphid_packet {
            Packet::Initialization(mut init_packet) => {
                debug!("Received initialization payload.");

                self.payload_stack.insert(
                    init_packet.channel.into(),
                    ChannelPayload {
                        data: Vec::with_capacity(init_packet.length as usize),
                        next_expected_sequence: 0,
                    },
                );

                let channel_payload = self
                    .payload_stack
                    .get_mut(&init_packet.channel.clone().into())
                    .unwrap();

                let take_count = channel_payload.data.capacity().min(init_packet.data.len());
                channel_payload
                    .data
                    .extend(init_packet.data.drain(..take_count));

                if channel_payload.data.len() < channel_payload.data.capacity() {
                    debug!("Initialization payload is incomplete, collecting additional packets.");
                    if let Err(err) = collect_all_packet(self) {
                        let device_error = err
                            .downcast_ref::<DeviceError>()
                            .copied()
                            .unwrap_or(DeviceError::Other);
                        self.send_portocal_error(init_packet.channel, device_error)?;
                        return Ok(None);
                    }
                    debug!("Additional packets have been collected.");
                }

                let completed_payload = self
                    .payload_stack
                    .remove(&init_packet.channel.into())
                    .unwrap();

                self.handle_ctaphid_command(
                    init_packet.command,
                    init_packet.channel,
                    completed_payload.data,
                )
            }
            // Continuation packets will be captured via collect_all_packet().
            // This code should only run if a continuous packet throws an error,
            // in which case the next sequence packet would be caught up here.
            Packet::Continuation(_) => unreachable!(),
        }
    }

    pub fn handle_ctaphid_command(
        &mut self,
        command: Command,
        channel: Channel,
        data: Vec<u8>,
    ) -> ReturnEvent {
        debug!("Received command {:?}", command);
        match command {
            Command::Ping => {
                self.send_response(channel, Command::Ping, data)?;
            }
            // ignore all cancel request.
            Command::Cancel => (),
            Command::Cbor => {
                return Ok(Some((channel, data)));
            }
            Command::Error => {
                error!(
                    "Communicator channel {}, is reporting an error with a payload: {:?}",
                    channel, data
                );
            }
            Command::Init => {
                // if self.channel.is_some() {
                //     self.send_error(channel, DeviceError::ChannelBusy)?;
                //     return Ok(None);
                // }
                // let channel = Some(generate_new_cid());

                let init_reply = InitResponse {
                    nonce: data[0..8].try_into()?,
                    channel: generate_new_cid(),
                    protocol_version: 0x02,
                    device_version: DeviceVersion {
                        major: 0x01,
                        minor: 0x00,
                        build: 0x00,
                    },
                    // https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-client-to-authenticator-protocol-v2.0-id-20180227.html#usb-hid-init
                    // According to spec, "If set to 1, authenticator DOES NOT implement CTAPHID_MSG function"
                    // as, it doesn't support NMSG, it is set to 1.
                    // though, it looks counter intuitive compared to other capabilitites.
                    capabilities: Capabilities::CBOR | Capabilities::NMSG,
                    rest: [0u8; 0],
                };

                let mut reply_data = [0u8; 17];
                init_reply.serialize(&mut reply_data)?;

                let report_structure = InitializationPacket {
                    channel: Channel::BROADCAST,
                    command: Command::Init,
                    data: reply_data,
                    length: reply_data.len() as u16,
                };

                let mut report = [0u8; 64];
                report_structure.serialize(&mut report)?;

                self.hid.write(&report)?;

                debug!("Acknowledged {:?}", command);
            }
            // This command code is sent while processing a CTAPHID_MSG.
            // Since it doesn't use legacy MSG and instead uses CTAP, it must be unreachable.

            // If it is reached, it means Chromium fallbacked to the legacy nmsg due to an error in CTAP communication.
            // However, even with the fallback, it won't be reached.
            Command::KeepAlive => unreachable!(),
            Command::Lock => {
                self.send_64response(channel, Command::Lock, &[])?;
            }
            Command::Message => {
                // let p = InitializationPacket {
                //     channel: self.channel.unwrap(),
                //     command: Command::Unknown(0x3 | 0x80),
                //     data: &[],
                //     length: 0,
                // }
                self.send_64response(channel, Command::Unknown(0x83), &[0x6D, 0x00])?;
            }
            Command::Unknown(_) => unimplemented!(),
            Command::Vendor(_) => unimplemented!(),
            Command::Wink => {
                self.send_64response(channel, Command::Wink, &[])?;
            }
        }
        debug!("Acknowledged {:?}", command);
        Ok(None)
    }

    pub fn send_64response<T: AsRef<[u8]>>(
        &mut self,
        channel: Channel,
        command: Command,
        data: T,
    ) -> anyhow::Result<()> {
        let packet = InitializationPacket {
            channel,
            command,
            length: data.as_ref().len() as u16,
            data,
        };
        let mut report = [0u8; 64];
        packet.serialize(&mut report)?;
        self.hid.write(&report)?;
        Ok(())
    }

    // pub fn free_channel(&mut self) {
    //     self.channel = None;
    // }

    pub fn send_response<T: AsRef<[u8]>>(
        &mut self,
        channel: Channel,
        command: Command,
        data: T,
    ) -> anyhow::Result<()> {
        let message = Message {
            channel,
            command: command,
            data,
        };
        let fragements = message.fragments(64).unwrap();
        let mut report = [0u8; 64];
        for packet in fragements {
            packet.serialize(&mut report)?;
            self.hid.write(&report)?;
        }
        Ok(())
    }

    pub fn send_portocal_error(
        &mut self,
        channel: Channel,
        err_code: DeviceError,
    ) -> anyhow::Result<()> {
        let packet = InitializationPacket {
            channel,
            command: Command::Error,
            length: 1,
            data: &[device_err_into_bytes(err_code)],
        };

        let mut report = [0u8; 64];
        packet.serialize(&mut report)?;
        self.hid.write(&report.to_vec())?;

        Ok(())
    }
}
