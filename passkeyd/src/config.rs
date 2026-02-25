use std::{collections::HashMap, fs};

// Either passkeyd has to run as a user with all required privilege groups, like TSS,
// or run passkeyd with elevated privileges.

// If run with passkeyd as a privilege, the GUI layer needs to be separated, and must run with lower privileges, which is a lot of work.
// BUT you can sleep peacefully knowing that even if the PC gets some malware,
// it can't access the TPM or create any VHID.
// Assuming the malware is also underprivileged, if it has higher privileges, well, well.
// If someone is dumb enough to run random stuff with privileges, they should just to Windows with windows defender turned on.

pub struct Config {
    pub gui_uid: u32, // UID to create a under privilege child, to prevent GUI from running as root
    #[allow(unused)]
    pub rust_log: String,
}

const PASSKEY_CONFIG_PATH: &str = "/etc/passkeyd.conf";

impl Config {
    pub fn initialize() -> anyhow::Result<Config> {
        let content = fs::read_to_string(PASSKEY_CONFIG_PATH)?;
        let config = content
            .lines()
            .filter(|line| line.is_empty() || line.trim_start().starts_with("#"))
            .filter_map(|line| {
                let mut parts = line.splitn(2, "=");
                Some((
                    parts.next()?.trim().to_string(),
                    parts.next()?.trim().to_string(),
                ))
            })
            .collect::<HashMap<String, String>>();

        let gui_uid = config
            .get("GUI_UID")
            .unwrap_or(&"1000".to_string())
            .parse()?;
        let rust_log = config
            .get("RUST_LOG")
            .unwrap_or(&if cfg!(debug_assertions) {
                "debug".to_string()
            } else {
                "error".to_string()
            })
            .to_string(); //No need to strictly check if RUST_LOG has a proper valid value
        unsafe {
            std::env::set_var("RUST_LOG", &rust_log);
        }
        env_logger::init();
        Ok(Config { gui_uid, rust_log })
    }
}
