mod old_db;
mod old_layout;
use std::fs;

use ctap_types::serde::cbor_deserialize;
use ctap_types::webauthn::PublicKeyCredentialRpEntity;
use passkeyd_abi::cryptography::CryptoPair;
use passkeyd_abi::database::layout;

use crate::old_db::database_dir;
use crate::old_layout::{Passkey, StoredPasskey};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    passkeyd_locale::init_translations();
    let db_path = database_dir();
    if !db_path.exists() {
        eprintln!(
            "{}",
            passkeyd_locale::translate!("migrate.main.database_not_found")
        );
        return Ok(());
    }
    let entries = fs::read_dir(db_path)?;

    'outer: for website_entry in entries {
        let website_path = website_entry?.path();

        if !website_path.is_dir() {
            continue;
        }

        let metadata_path = website_path.join("metadata");
        if !metadata_path.exists() {
            continue;
        }

        for passkey_entry in fs::read_dir(&website_path)? {
            let passkey_entry = passkey_entry?;
            let file_name = passkey_entry.file_name();

            if file_name == "metadata" {
                continue;
            }

            let passkey_bytes = fs::read(passkey_entry.path())?;

            let stored_passkey: StoredPasskey = match cbor_deserialize(&passkey_bytes) {
                Ok(val) => val,
                Err(_) => {
                    eprintln!(
                        "{}",
                        passkeyd_locale::translate!("migrate.main.malfored_passkey")
                    );
                    continue;
                }
            };

            // Convert StoredPasskey -> Passkey
            let old_passkey_model: Passkey = match stored_passkey.try_into() {
                Ok(val) => val,
                Err(_) => {
                    eprintln!(
                        "{}",
                        passkeyd_locale::translate!("migrate.main.malfored_passkey")
                    );
                    continue;
                }
            };

            if old_passkey_model.credential_source.rp_id.as_str() == ".dummy" {
                continue 'outer;
            }

            let crypto_pair = CryptoPair::TPM((
                old_passkey_model
                    .credential_source
                    .private_key
                    .try_into()
                    .unwrap(),
                old_passkey_model
                    .credential_source
                    .public_key
                    .try_into()
                    .unwrap(),
            ));

            let new_passkey_model = layout::Passkey::new(
                old_passkey_model.credential_source.rp_id.clone(),
                old_passkey_model.credential_source.other_ui.user.clone(),
                crypto_pair,
            );

            let mock_rp = PublicKeyCredentialRpEntity {
                icon: None,
                id: old_passkey_model.credential_source.rp_id.clone(),
                name: None,
            };
            new_passkey_model.store(mock_rp);

            println!(
                "{}",
                passkeyd_locale::translate!(
                    "migrate.main.migration_success",
                    site => old_passkey_model.credential_source.rp_id.to_string(),
                    user_account => String::from_utf8_lossy(&old_passkey_model.credential_source.other_ui.user.id)
                )
            );
        }
    }
    Ok(())
}
