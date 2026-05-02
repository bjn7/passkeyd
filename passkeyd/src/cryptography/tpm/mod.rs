mod es256;
mod rs256;

#[allow(clippy::module_inception)]
mod tpm;

use log::warn;
use passkeyd_abi::{
    cryptography::{CryptoBackend, CryptoPair},
    utils::{Cose, encode_cose_es256, encode_cose_rs256},
};
use tss_esapi::{Context, handles::KeyHandle};

use crate::cryptography::{translate_es256_to_der, r#virtual::Virtual};

pub struct Tpm {
    ctx: Context,
    srk_key_handle: KeyHandle,
}

impl Tpm {
    pub fn new() -> anyhow::Result<Tpm> {
        let mut ctx = tpm::initialize_tpm_with_session()?;
        let srk_key_handle = tpm::create_primary_key_handle(&mut ctx)?;
        Ok(Self {
            ctx,
            srk_key_handle,
        })
    }
}

impl CryptoBackend for Tpm {
    fn generate_es256_keypair(&mut self) -> anyhow::Result<(CryptoPair, Cose)> {
        let (pr, pu) = es256::make_cerd(&mut self.ctx, &self.srk_key_handle)?;
        match &pu {
            tss_esapi::structures::Public::Ecc {
                object_attributes: _,
                name_hashing_algorithm: _,
                auth_policy: _,
                parameters: _,
                unique,
            } => {
                let tpm_crypto_pair = CryptoPair::TPM((pr, pu.clone()));
                let cose = encode_cose_es256(
                    unique.x().as_array().unwrap(),
                    unique.y().as_array().unwrap(),
                );
                Ok((tpm_crypto_pair, cose))
            }
            _ => unreachable!(),
        }
    }

    fn generate_rs256_keypair(&mut self) -> anyhow::Result<(CryptoPair, Cose)> {
        let (pr, pu) = rs256::make_cerd(&mut self.ctx, &self.srk_key_handle)?;
        match &pu {
            tss_esapi::structures::Public::Rsa {
                object_attributes: _,
                name_hashing_algorithm: _,
                auth_policy: _,
                parameters,
                unique,
            } => {
                let tpm_crypto_pair = CryptoPair::TPM((pr, pu.clone()));
                let e: [u8; 4] = parameters.exponent().value().to_be_bytes();
                let n = unique.value().as_array().unwrap();
                let cose = encode_cose_rs256(n, e[1..].as_array().unwrap());
                Ok((tpm_crypto_pair, cose))
            }
            _ => unreachable!(),
        }
    }

    fn sign_payload(
        &mut self,
        crypto_pair: CryptoPair,
        payload: &[u8],
    ) -> anyhow::Result<(i32, Vec<u8>)> {
        if let CryptoPair::TPM((pr, pu)) = crypto_pair {
            let signature = tpm::sign(&mut self.ctx, &self.srk_key_handle, pr, pu, payload)?;

            match signature {
                tss_esapi::structures::Signature::EcDsa(sig) => Ok((
                    -7,
                    translate_es256_to_der(
                        sig.signature_r().as_slice(),
                        sig.signature_s().as_slice(),
                    ),
                )),
                tss_esapi::structures::Signature::RsaSsa(sig) => {
                    Ok((-257, sig.signature().to_vec()))
                }
                _ => unreachable!(),
            }
        } else {
            warn!("Using virtual singing, even though the configuration is set to TPM.");
            Virtual::sign_payload(&mut Virtual, crypto_pair, payload)
        }
    }
}
