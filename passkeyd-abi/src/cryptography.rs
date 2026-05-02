use ctap_types::webauthn::PublicKeyCredentialRpEntity;
use p256::ecdsa;
use serde::{Deserialize, Serialize};
use serde::{Deserializer, Serializer};
use sha2::Sha256;
use tss_esapi::structures::{Private, Public};

use crate::database::layout::Passkey;
use crate::utils::Cose;

#[derive(Serialize, Deserialize, Clone)]
pub enum VirtualKeyPair {
    #[serde(with = "es256_codec")]
    Es256(ecdsa::SigningKey, ecdsa::VerifyingKey),
    #[serde(with = "rs256_codec")]
    Rs256(Box<RsaKeyPairType>),
}

type RsaKeyPairType = (
    rsa::pkcs1v15::SigningKey<Sha256>,
    rsa::pkcs1v15::VerifyingKey<Sha256>,
);

#[derive(Serialize, Deserialize, Clone)]
pub enum CryptoPair {
    #[serde(with = "tpm_codec")]
    TPM((Private, Public)),
    Virtual(Box<VirtualKeyPair>),
}

pub trait CryptoBackend {
    fn generate_es256_keypair(&mut self) -> anyhow::Result<(CryptoPair, Cose)>;
    fn generate_rs256_keypair(&mut self) -> anyhow::Result<(CryptoPair, Cose)>;
    fn sign_payload(
        &mut self,
        crypto_pair: CryptoPair,
        payload: &[u8],
    ) -> anyhow::Result<(i32, Vec<u8>)>;
}

pub trait StorageBackend {
    fn set_passkey(
        &mut self,
        rp: PublicKeyCredentialRpEntity,
        passkey: Passkey,
    ) -> anyhow::Result<()>;
    fn get_passkey(&mut self, rp: PublicKeyCredentialRpEntity) -> anyhow::Result<Vec<Passkey>>;
    fn increment_sign_count(
        &mut self,
        rp: PublicKeyCredentialRpEntity,
    ) -> anyhow::Result<Vec<Passkey>>;
    fn get_passkeys(&mut self, rp: PublicKeyCredentialRpEntity) -> anyhow::Result<Vec<Passkey>>;
}

mod es256_codec {
    use super::*;

    #[derive(Serialize, Deserialize)]
    struct Helpers {
        sign_key: Vec<u8>,
        verify_key: Vec<u8>,
    }

    pub fn serialize<S>(
        sk: &ecdsa::SigningKey,
        vk: &ecdsa::VerifyingKey,
        s: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let data = Helpers {
            sign_key: sk.to_bytes().to_vec(),
            verify_key: vk.to_encoded_point(true).as_bytes().to_vec(),
        };
        data.serialize(s)
    }

    pub fn deserialize<'de, D>(d: D) -> Result<(ecdsa::SigningKey, ecdsa::VerifyingKey), D::Error>
    where
        D: Deserializer<'de>,
    {
        let helper = Helpers::deserialize(d)?;
        let sk =
            ecdsa::SigningKey::from_slice(&helper.sign_key).map_err(serde::de::Error::custom)?;
        let vk = ecdsa::VerifyingKey::from_sec1_bytes(&helper.verify_key)
            .map_err(serde::de::Error::custom)?;
        Ok((sk, vk))
    }
}

mod rs256_codec {
    use super::*;
    use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};

    #[derive(Serialize, Deserialize)]
    struct Helpers {
        priv_der: Vec<u8>,
        pub_der: Vec<u8>,
    }

    pub fn serialize<S>(
        val: &(
            rsa::pkcs1v15::SigningKey<Sha256>,
            rsa::pkcs1v15::VerifyingKey<Sha256>,
        ),
        s: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let (sk, vk) = val;
        let priv_der = sk
            .as_ref()
            .to_pkcs8_der()
            .map_err(serde::ser::Error::custom)?;
        let pub_der = vk
            .as_ref()
            .to_public_key_der()
            .map_err(serde::ser::Error::custom)?;

        Helpers {
            priv_der: priv_der.as_bytes().to_vec(),
            pub_der: pub_der.to_vec(),
        }
        .serialize(s)
    }

    pub fn deserialize<'de, D>(d: D) -> Result<Box<RsaKeyPairType>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let helper = Helpers::deserialize(d)?;
        let priv_key = rsa::RsaPrivateKey::from_pkcs8_der(&helper.priv_der)
            .map_err(serde::de::Error::custom)?;
        let pub_key = rsa::RsaPublicKey::from_public_key_der(&helper.pub_der)
            .map_err(serde::de::Error::custom)?;

        Ok(Box::new((
            rsa::pkcs1v15::SigningKey::new(priv_key),
            rsa::pkcs1v15::VerifyingKey::new(pub_key),
        )))
    }
}

mod tpm_codec {
    use tss_esapi::traits::{Marshall, UnMarshall};

    use super::*;
    #[derive(Serialize, Deserialize)]
    struct TpmBytes {
        priv_blob: Vec<u8>,
        pub_blob: Vec<u8>,
    }

    pub fn serialize<S>(pair: &(Private, Public), s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let data = TpmBytes {
            priv_blob: pair.0.to_vec(),
            pub_blob: pair.1.marshall().map_err(serde::ser::Error::custom)?,
        };
        data.serialize(s)
    }

    pub fn deserialize<'de, D>(d: D) -> Result<(Private, Public), D::Error>
    where
        D: Deserializer<'de>,
    {
        let helper = TpmBytes::deserialize(d)?;

        let priv_key = Private::try_from(helper.priv_blob).map_err(serde::de::Error::custom)?;
        let pub_key = Public::unmarshall(&helper.pub_blob).map_err(serde::de::Error::custom)?;

        Ok((priv_key, pub_key))
    }
}
