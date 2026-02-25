use ctap_types::{serde::cbor_deserialize, webauthn::PublicKeyCredentialRpEntity};
use sha2::Digest;
use std::{fs, path::PathBuf};
pub mod layout;
use layout::{Passkey, StoredPasskey};
use log::info;

use crate::utils::CborVec;

#[cfg(debug_assertions)]
const FSBASE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/TEMPP_DATABASE");

#[cfg(not(debug_assertions))]
const FSBASE: &str = "/var/lib/passkeyd/database";

// impl From<PrivateWrapper> for Private {
//     fn from(wrapper: PrivateWrapper) -> Private {
//         Private::try_from(wrapper.bytes).expect("Invalid Private bytes")
//     }
// }

// impl From<PublicKeyCredentialRpEntity> for Passkey {}

// A metadata is a PublicKeyCredentialRpEntity
// and suffixed with "table" is a PathBuf

fn update_metadata(rp: &PublicKeyCredentialRpEntity, rp_path: &PathBuf) {
    let metadata_path = rp_path.join("metadata");
    let meta = CborVec::with_object(rp, size_of::<PublicKeyCredentialRpEntity>());
    fs::write(metadata_path, meta).expect("failed to update metadata");
}

fn get_metadata(rp_path: &PathBuf) -> PublicKeyCredentialRpEntity {
    let metadata_path = rp_path.join("metadata"); // path will always exist
    let cbor_buff = fs::read(metadata_path).expect("failed to update metadata");
    cbor_deserialize(&cbor_buff).expect("Failed to encode into cbor")
}

fn get_rp_table(rp: &PublicKeyCredentialRpEntity, create: bool) -> Option<PathBuf> {
    let rp_hash = sha2::Sha256::digest(&rp.id.as_bytes());
    let rp_hex_hash = hex::encode(rp_hash);
    let rp_table = PathBuf::from(FSBASE).join(rp_hex_hash);
    if rp_table.exists() {
        Some(rp_table)
    } else if create {
        fs::create_dir(&rp_table).expect("Failed to create dir, are you root?");
        update_metadata(rp, &rp_table);
        Some(rp_table)
    } else {
        None
    }
}

fn get_table(
    rp: &PublicKeyCredentialRpEntity,
    credential_id: &[u8],
    create: bool,
) -> Option<PathBuf> {
    match get_rp_table(rp, create) {
        Some(rp_table) => {
            let user_table = rp_table.join(cerdential_id_to_str(credential_id));
            if user_table.exists() {
                Some(user_table)
            } else if create {
                fs::File::create(&user_table)
                    .expect("Failed to create file, do you have permission?");
                Some(user_table)
            } else {
                None
            }
        }
        None => None,
    }
}

pub fn get_passkey(
    rp: &PublicKeyCredentialRpEntity,
    credential_id: &[u8],
) -> Option<(PublicKeyCredentialRpEntity, Passkey)> {
    let table = get_table(&rp, credential_id, false);
    if let Some(mut table) = table {
        let cbor_data = fs::read(&table).unwrap();
        let data: StoredPasskey =
            cbor_deserialize(&cbor_data).expect("Failed to translate to cbor");
        let metadata = get_metadata({
            table.pop();
            &table
        });
        Some((
            metadata,
            data.passkey
                .try_into()
                .expect("decryption failed, are you root?"),
        ))
    } else {
        return None;
    }
}

pub fn get_passkeys(
    rp: &PublicKeyCredentialRpEntity,
) -> Option<(PublicKeyCredentialRpEntity, Vec<Passkey>)> {
    let table = get_rp_table(&rp, false);
    if let Some(table) = table {
        // let cbor_data = fs::read(table).unwrap();
        // cbor_deserialize(&cbor_data).expect("Failed to translate to cbor")
        let metadata = get_metadata(&table);
        let dir_entires = fs::read_dir(table)
            .expect("Failed to read dir, Do you have a permission?")
            .collect::<Vec<_>>();
        let mut passkeys: Vec<Passkey> = Vec::with_capacity(dir_entires.len());
        for entry in dir_entires {
            let table = entry
                .expect("Failed to read dir entry, do you have a permission?")
                .path();
            if table.ends_with("metadata") {
                continue;
            }
            let cbor_data = fs::read(table).unwrap();
            let data: StoredPasskey =
                cbor_deserialize(&cbor_data).expect("Failed to translate to cbor");
            passkeys.push(
                data.passkey
                    .try_into()
                    .expect("decryption failed, are you root?"),
            );
        }
        Some((metadata, passkeys))
    } else {
        None
        // return Vec::new();
    }
}

pub fn set_passkey(rp: PublicKeyCredentialRpEntity, passkey: Passkey) {
    let table = get_table(&rp, passkey.credential_source.id.as_slice(), true).unwrap();
    let storeable: StoredPasskey = passkey.into();
    // cbor_serialize_to(&storeable, &mut cbor_data).expect("Failed to translate to cbor");
    fs::write(table, CborVec::with_object(storeable, size_of::<Passkey>()))
        .expect("Failed to cbor data into file");

    info!("Passkey has been stored");
}

pub fn increment_sign_count(rp: PublicKeyCredentialRpEntity, mut passkey: Passkey) {
    let table = get_table(&rp, passkey.credential_source.id.as_slice(), true).unwrap();
    passkey.sign_count += 1;
    let storeable: StoredPasskey = passkey.into();
    fs::write(table, CborVec::with_object(storeable, size_of::<Passkey>()))
        .expect("Failed to cbor data into file");

    info!("Sign count has been updated");
}

fn cerdential_id_to_str(id: &[u8]) -> String {
    hex::encode(id)
    // id.iter()
    //     .map(|x| x.to_string())
    //     .collect::<Vec<String>>()
    //     .join("-")
}
