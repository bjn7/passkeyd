use std::time::Duration;

use bytes::Bytes;
use ctap_types::{
    serde::cbor_deserialize,
    webauthn::{PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity},
};

use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::{
    cryptography::CryptoPair,
    database::{get_passkey, increment_sign_count, set_passkey},
    utils::CborVec,
};

#[derive(Serialize, Deserialize)]
pub enum CredentialType {
    PublicKey,
}

#[derive(Serialize, Deserialize)]
pub struct OtherUI {
    pub user: PublicKeyCredentialUserEntity,
    pub site_icon: Option<bytes::Bytes>,
    pub user_icon: Option<bytes::Bytes>,
}

#[derive(Serialize, Deserialize)]
pub struct CredentialSource {
    // According to spec,
    // If requireResidentKey is true or the authenticator chooses to create a client-side discoverable public key credential source:
    // Let credentialId be a new credential id.
    // Set credentialSource.id to credentialId.
    pub id: [u8; 32], //but unlike spec, it wil always be a cerdential ID
    // r#type: "public-key",
    pub crypto_pair: CryptoPair,
    pub rp_id: ctap_types::String<256>,
    pub user_handle: ctap_types::Bytes<64>, //userEntity.id
    pub other_ui: OtherUI,
}

#[derive(Serialize, Deserialize)]
pub struct Passkey {
    pub sign_count: u32,
    // pub credential_id: [u8; 32],
    pub credential_type: CredentialType,
    pub credential_source: CredentialSource,
}

#[derive(Serialize, Deserialize)]
pub struct StoreablePasskey(Vec<u8>); //why store in cbor instead of sotring directly? well idk, why not do it ? free will??

impl Passkey {
    pub fn new(
        rp_id: ctap_types::String<256>,
        user: PublicKeyCredentialUserEntity,
        crypto_pair: CryptoPair,
    ) -> Self {
        let mut credential_id = [0u8; 32];
        rand::rng().fill_bytes(&mut credential_id);

        let mut other_ui = OtherUI {
            site_icon: None,
            user,
            user_icon: None,
        };

        if let Some(user_icon_url) = &other_ui.user.icon {
            let result = ureq::get(user_icon_url.as_str())
                .config()
                .timeout_global(Some(Duration::from_secs(5)))
                .build()
                .call()
                .ok();
            other_ui.user_icon = result
                .and_then(|mut x| x.body_mut().read_to_vec().ok())
                .map(Bytes::from_owner);
        };

        other_ui.site_icon = None;
        // if let Some(site_icon_url) = &other_ui.user.icon {
        //     let result = ureq::get(site_icon_url.as_str())
        //         .config()
        //         .timeout_global(Some(Duration::from_secs(5)))
        //         .build()
        //         .call()
        //         .ok();
        //     other_ui.site_icon = result
        //         .and_then(|mut x| x.body_mut().read_to_vec().ok())
        //         .map(|x| Bytes::from_owner(x));
        // };

        let source = CredentialSource {
            id: credential_id,
            user_handle: other_ui.user.id.clone(),
            other_ui,
            rp_id,
            crypto_pair,
        };

        Self {
            sign_count: 0,
            credential_type: CredentialType::PublicKey,
            credential_source: source,
        }
    }

    pub fn store(self, rp: PublicKeyCredentialRpEntity) {
        set_passkey(rp, self);
    }

    pub fn sign_increment(self, rp: PublicKeyCredentialRpEntity) {
        increment_sign_count(rp, self);
    }

    pub fn get(
        rp: &PublicKeyCredentialRpEntity,
        credential_id: &[u8],
    ) -> Option<(PublicKeyCredentialRpEntity, Self)> {
        get_passkey(rp, credential_id)
    }
}

impl TryInto<Passkey> for StoreablePasskey {
    type Error = ctap_types::serde::Error;
    fn try_into(self) -> Result<Passkey, Self::Error> {
        cbor_deserialize(&self.0)
    }
}

impl From<Passkey> for StoreablePasskey {
    fn from(value: Passkey) -> Self {
        Self(CborVec::from_serializable(value, size_of::<Passkey>()).into_inner())
    }
}
