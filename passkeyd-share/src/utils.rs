// use std::ops::{Deref, DerefMut};
use ctap_types::serde::{cbor_serialize_to, ser::Writer};
use log::debug;
use serde::Serialize;
use std::{
    io::Write,
    process::{Child, Stdio},
};

use crate::config::Config;

pub struct CborVec(pub Vec<u8>);

impl CborVec {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn with_size_hint(hint: usize) -> Self {
        Self(Vec::with_capacity(hint))
    }
    pub fn take_inner(self) -> Vec<u8> {
        self.0
    }

    pub fn with_object<T>(obj: T, size_hint: usize) -> Self
    where
        T: Serialize,
    {
        let mut cbor_data = CborVec::with_size_hint(size_hint);
        cbor_serialize_to(&obj, &mut cbor_data).expect("Failed to translate to cbor");
        cbor_data
    }
}

impl Writer for CborVec {
    type Error = ctap_types::serde::Error;
    fn write_all(&mut self, buf: &[u8]) -> ctap_types::serde::Result<(), Self::Error> {
        self.0.extend_from_slice(buf);
        Ok(())
    }
}

// impl Deref for CborVec {
//     type Target = Vec<u8>;
//     fn deref(&self) -> &Self::Target {
//         &self.0
//     }
// }

// impl DerefMut for CborVec {
//     fn deref_mut(&mut self) -> &mut Self::Target {
//         &mut self.0
//     }
// }

impl AsRef<[u8]> for CborVec {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

pub enum Cose {
    ES256([u8; 77]),
    RS256([u8; 273]),
}

pub fn encode_cose_es256(x: &[u8; 32], y: &[u8; 32]) -> Cose {
    let mut out = [0u8; 77];
    out[0] = 0xA5; //map with 5 elementss

    out[1] = 0x01; //key type (1) 
    out[2] = 0x02; //ec2 (2)

    out[3] = 0x03; //ago 3
    out[4] = 0x26; // es256 -7

    out[5] = 0x20; //crv 
    out[6] = 0x01; //256 1

    out[7] = 0x21; // x -2
    out[8] = 0x58; // byte string header
    out[9] = 0x20; //32 byte header
    out[10..10 + 32].copy_from_slice(x);

    out[42] = 0x22; // x -3
    out[43] = 0x58; // byte string header
    out[44] = 0x20; //32 byte header
    out[45..45 + 32].copy_from_slice(y);
    Cose::ES256(out)
}

pub fn encode_cose_rs256(n: &[u8; 256], e: &[u8; 3]) -> Cose {
    let mut out = [0u8; 273];
    out[0] = 0xA4; //map with 4 elementss

    out[1] = 0x01; //key type (3) 
    out[2] = 0x03; //rsa (2)

    out[3] = 0x03; //ago 3
    out[4] = 0x39; // header for int, 2 byte argument
    out[5] = 0x01; // 256
    out[6] = 0x00; // -1-256 = -257

    out[7] = 0x20; // n -1
    out[8] = 0x59; // byte string, 2 byte length
    out[9] = 0x01; // len 256
    out[10] = 0x00;
    out[11..11 + 256].copy_from_slice(n);

    out[267] = 0x21; // e -2
    // out[268] = 0x58; // label 2
    out[268] = 0x43; // byte string, len 3
    out[269..269 + 3].copy_from_slice(e);
    Cose::RS256(out)
}

pub enum UI {
    KeyEnroll,
    KeySelect,
}

impl UI {
    #[allow(unused)]
    fn as_str_path(&self, config: &Config) -> String {
        #[cfg(debug_assertions)]
        {
            use std::{env, path::Path};
            let target_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../target/debug")
                .canonicalize()
                .unwrap()
                .to_string_lossy()
                .to_string();
            match self {
                UI::KeyEnroll => format!("{target_dir}/{}", "passkeyd-enroll"),
                UI::KeySelect => format!("{target_dir}/{}", "passkeyd-select"),
            }
        }

        #[cfg(not(debug_assertions))]
        {
            match self {
                UI::KeyEnroll => format!("/usr/lib/passkeyd/{}", config.front_enroll.as_str()),
                UI::KeySelect => format!("/usr/lib/passkeyd/{}", config.front_select.as_str()),
            }
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
