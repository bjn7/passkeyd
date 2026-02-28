use crate::config::Config;
use ctap_types::serde::cbor_serialize_to;
use der::{Encode, Sequence, asn1::UintRef};
use log::debug;
use serde::Serialize;
use std::{
    io::Write,
    process::{Child, Stdio},
};

use super::utils::CborVec;

pub const ALGO_ES256: i32 = -7;
// pub const ALGO_EDDSA: i32 = -8; (isn't support by tpm)
pub const ALGO_RS256: i32 = -257;

pub mod get;
pub mod make;

// UTILITY
pub enum UI {
    KeyEnroll,
    KeySelect,
}

impl UI {
    fn as_str_path(&self, config: &Config) -> String {
        match (self, cfg!(debug_assertions)) {
            (UI::KeyEnroll, true) => {
                "/home/stranger/Code/passkey/target/debug/passkeyd-enroll".into()
            } //for dev
            (UI::KeyEnroll, false) => format!("/usr/lib/passkeyd/{}", config.front_enroll.as_str()),

            (UI::KeySelect, true) => {
                "/home/stranger/Code/passkey/target/debug/passkeyd-select".into()
            } //for dev
            (UI::KeySelect, false) => format!("/usr/lib/passkeyd/{}", config.front_select.as_str()),
        }
    }
}

// Util function
pub fn spawn_ui<State>(config: &Config, ui: UI, state: State) -> Child
where
    State: Serialize,
{
    let mut state_buffer = CborVec::new();
    let cbor = cbor_serialize_to(&state, &mut state_buffer).unwrap();
    debug!("Spawning ui");
    let mut command = std::process::Command::new("systemd-run")
        .arg(format!("--machine={}@", config.gui_uid))
        .arg("--user")
        .arg("--collect")
        .arg("--wait")
        .arg("--quiet")
        .arg("--pipe")
        .arg(ui.as_str_path(config))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to spawn UI, are you root?");
    let mut stdin = command.stdin.take().expect("Failed to get stdin");
    stdin
        .write_all(&state_buffer.0[..cbor])
        .expect("Failed to write into pipe");
    return command;
}

#[derive(Sequence)]
struct EcdsaSignature<'a> {
    pub r: UintRef<'a>,
    pub s: UintRef<'a>,
}
fn translate_es256_to_der(r_bytes: &[u8], s_bytes: &[u8]) -> Vec<u8> {
    let sig = EcdsaSignature {
        r: UintRef::new(&r_bytes).expect("invalid r"),
        s: UintRef::new(&s_bytes).expect("invalid s"),
    };
    sig.to_der().expect("DER-ASN.1 encoding failed")
}
