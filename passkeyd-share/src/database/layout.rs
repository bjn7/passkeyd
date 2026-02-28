use std::time::Duration;

use bytes::Bytes;
use ctap_types::{
    serde::{cbor_deserialize, cbor_serialize_to},
    webauthn::{PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity},
};

use rand::RngCore;
use serde::{Deserialize, Serialize};
use tss_esapi::{
    structures::{Private, Public},
    traits::{Marshall, UnMarshall},
};

use crate::{
    database::{get_passkey, increment_sign_count, set_passkey},
    utils::CborVec,
};

#[derive(Serialize, Deserialize, Clone)]
pub struct StoreableKey(Vec<u8>);

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
    pub private_key: StoreableKey,
    pub public_key: StoreableKey,
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

#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptedPassKey(Vec<u8>);

#[derive(Serialize, Deserialize, Debug)]
pub struct StoredPasskey {
    pub passkey: EncryptedPassKey,
    // pub private_key: StoreableKey, //the actuall wrapped private key
}

impl Passkey {
    pub fn new(
        private_key: Private,
        public_key: Public,
        rp_id: ctap_types::String<256>,
        user: PublicKeyCredentialUserEntity,
    ) -> Self {
        let mut credential_id = [0u8; 32];
        rand::rng().fill_bytes(&mut credential_id);

        let mut other_ui = OtherUI {
            site_icon: None,
            user: user,
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
                .map(|x| Bytes::from_owner(x));
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
            private_key: private_key.try_into().expect("Failed to marshallel"),
            other_ui: other_ui,
            public_key: public_key.clone().try_into().expect("Failed to marshallel"),
            rp_id: rp_id.clone(),
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
        get_passkey(&rp, credential_id)
    }
}

impl TryInto<Passkey> for StoredPasskey {
    type Error = ctap_types::serde::Error;
    fn try_into(self) -> Result<Passkey, Self::Error> {
        self.passkey.try_into()
    }
}

impl From<Passkey> for StoredPasskey {
    fn from(value: Passkey) -> Self {
        Self {
            passkey: value.into(),
        }
    }
}

impl From<Passkey> for EncryptedPassKey {
    fn from(value: Passkey) -> Self {
        // The files are stored at a higher privilege level.
        // There is no threat actor in this scenario that requires them to be stored encrypted.
        // This is included only as a precaution, in case a user wants to store them encrypted in the future
        // for backup purposes especially to protect the privacy of stored sites and accounts.
        // Although the files are non‑human‑readable, a targeted threat actor could still read them.
        //
        // Even with a compromised device, and even with a higher‑privileged actor,
        // the system must be designed so that the files can still be read,
        // because they are encoded and require the same data layout.
        // This means targeted intent is required.
        //
        // Additionally, if an attacker already has TPM access,
        // a targeted threat actor could simply use the TPM to decrypt the data.
        //
        // Therefore, there is no need to encrypt the PassKey,
        // an encrypted private key is sufficient.

        // By above reasoning, this will be only plain cbor serialized data
        // Well, it was for following the standard, but I don't really need to

        // I don't think the site checks the length of a non-RK credential ID
        // to determine that it isn't an Obaq blob and reject the request.
        // This might occur at the enterprise level, but the target is an average user, not an enterprise.
        let mut v = CborVec::with_size_hint(size_of::<Passkey>());
        cbor_serialize_to(&value, &mut v).unwrap();
        EncryptedPassKey(v.take_inner())
    }
}

impl TryInto<Passkey> for EncryptedPassKey {
    type Error = ctap_types::serde::Error;
    fn try_into(self) -> Result<Passkey, Self::Error> {
        match cbor_deserialize(&self.0) {
            Ok(e) => Ok(e),
            Err(err) => Err(err),
        }
    }
}

impl From<Private> for StoreableKey {
    fn from(value: Private) -> Self {
        StoreableKey(value.to_vec())
    }
}

impl TryFrom<Public> for StoreableKey {
    type Error = tss_esapi::Error;
    fn try_from(value: Public) -> Result<Self, Self::Error> {
        let x = value.marshall()?;
        Ok(StoreableKey(x))
    }
}

impl TryInto<Private> for StoreableKey {
    type Error = tss_esapi::Error;
    fn try_into(self) -> Result<Private, Self::Error> {
        Private::try_from(self.0)
    }
}
impl TryInto<Public> for StoreableKey {
    type Error = tss_esapi::Error;
    fn try_into(self) -> Result<Public, Self::Error> {
        Public::unmarshall(&self.0)
    }
}
