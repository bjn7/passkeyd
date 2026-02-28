use anyhow::Ok;
use ctaphid_types::{Channel, DeviceError, Packet};
use log::{debug, error};
use rand::{RngCore, rng};

use crate::ctaphid::{ctaphid::Ctaphid, hid::OutputEvent};

pub fn generate_new_cid() -> Channel {
    let mut cid = [0u8; 4];
    rng().fill_bytes(&mut cid);
    Channel::from(cid)
}

pub fn collect_all_packet(
    ctaphid: &mut Ctaphid,
    // payload_buffer: &mut Vec<u8>,
    // next_sequence: u8,
) -> anyhow::Result<()> {
    let event = ctaphid.hid.read().expect("Failed to read hid events");
    if let OutputEvent::Output { data: report_bytes } = event {
        let raw_payload = &report_bytes[1..];
        let ctaphid_packet: Packet<Vec<u8>> = Packet::try_from(&raw_payload[..]).unwrap();
        match ctaphid_packet {
            Packet::Continuation(continuation_packet) => {
                let channel_payload = ctaphid
                    .payload_stack
                    .get_mut(&continuation_packet.channel.into())
                    .ok_or_else(|| {
                        error!("Invalid channel received: {}", continuation_packet.channel);
                        DeviceError::InvalidChannel
                    })?;

                if continuation_packet.sequence != channel_payload.next_expected_sequence {
                    println!(
                        "Sequence mismatch: received {}, expected {}",
                        continuation_packet.sequence, channel_payload.next_expected_sequence
                    );
                    anyhow::bail!(DeviceError::InvalidSequence);
                }

                let remaining_bytes = channel_payload.data.capacity() - channel_payload.data.len();
                let chunk_size = continuation_packet.data.len().min(remaining_bytes);
                channel_payload
                    .data
                    .extend_from_slice(&continuation_packet.data[..chunk_size]);

                debug!(
                    "[Packet Collector] [Channel: {}]: Seq: {}, Accumulated {}/{} bytes",
                    continuation_packet.channel,
                    continuation_packet.sequence,
                    channel_payload.data.len(),
                    channel_payload.data.capacity()
                );

                if channel_payload.data.len() >= channel_payload.data.capacity() {
                    debug!(
                        "[Packet Collector] [Channel: {}]: All packets have been accumulated.",
                        continuation_packet.channel
                    );
                    Ok(())
                } else {
                    // recursively collect more packets
                    channel_payload.next_expected_sequence += 1;
                    collect_all_packet(ctaphid)
                }
            }
            Packet::Initialization(_) => {
                // In case an initialization packet is received while collecting continuation packets
                ctaphid.event_handler(OutputEvent::Output { data: report_bytes })?;
                Ok(())
            }
        }
    } else {
        ctaphid.event_handler(event)?;
        Ok(())
    }
}

pub fn device_err_into_bytes(err: DeviceError) -> u8 {
    match err {
        DeviceError::InvalidCommand => 0x01,   // ERR_INVALID_CMD
        DeviceError::InvalidParameter => 0x02, // ERR_INVALID_PAR
        DeviceError::InvalidLength => 0x03,    // ERR_INVALID_LEN
        DeviceError::InvalidSequence => 0x04,  // ERR_INVALID_SEQ
        DeviceError::MessageTimeout => 0x05,   // ERR_MSG_TIMEOUT
        DeviceError::ChannelBusy => 0x06,      // ERR_CHANNEL_BUSY
        DeviceError::LockRequired => 0x0A,     // ERR_LOCK_REQUIRED (Standard value is 0x0A)
        DeviceError::InvalidChannel => 0x0B,   // ERR_INVALID_CID (Standard value is 0x0B)
        DeviceError::Other => 0x7F,            // ERR_OTHER (Standard value is 0x7F)
        DeviceError::Unknown(e) => e,
    }
}
