mod es256;
mod rs256;

use log::warn;
use passkeyd_abi::{
    cryptography::{CryptoBackend, CryptoPair, VirtualKeyPair},
    utils::{Cose, encode_cose_es256, encode_cose_rs256},
};
use rsa::{signature::SignerMut, traits::PublicKeyParts};

use crate::cryptography::tpm::Tpm;

pub struct Virtual;

impl CryptoBackend for Virtual {
    fn generate_es256_keypair(&mut self) -> anyhow::Result<(CryptoPair, Cose)> {
        let (pr, pu) = es256::make_cerd()?;
        let points = pu.to_encoded_point(false);
        let x = points.x().unwrap();
        let y = points.y().unwrap();
        let cose = encode_cose_es256(x.as_slice().try_into()?, y.as_slice().try_into()?);
        Ok((
            CryptoPair::Virtual(Box::new(VirtualKeyPair::Es256(pr, pu))),
            cose,
        ))
    }

    fn generate_rs256_keypair(&mut self) -> anyhow::Result<(CryptoPair, Cose)> {
        let (pr, pu) = rs256::make_cerd()?;
        let pub_key = pu.as_ref();
        let n = pub_key.n().to_bytes_be();
        let e = pub_key.e().to_bytes_be();
        let e_bytes = {
            let mut buf = [0u8; 3];
            let slice = &mut buf[3 - e.len()..];
            slice.copy_from_slice(e.get(..3).ok_or_else(|| {
                anyhow::anyhow!("RSA exponent is unexpectedly large (greater than 3 bytes)")
            })?);
            buf
        };

        let cose = encode_cose_rs256(&n.try_into().unwrap(), &e_bytes);
        Ok((
            CryptoPair::Virtual(Box::new(VirtualKeyPair::Rs256(Box::new((pr, pu))))),
            cose,
        ))
    }
    fn sign_payload(
        &mut self,
        crypto_pair: CryptoPair,
        payload: &[u8],
    ) -> anyhow::Result<(i32, Vec<u8>)> {
        if let CryptoPair::Virtual(virtual_key_pair) = crypto_pair {
            match *virtual_key_pair {
                VirtualKeyPair::Es256(mut pr, _) => {
                    let signature: p256::ecdsa::Signature = pr.sign(payload);
                    Ok((-7, signature.to_der().to_bytes().to_vec()))
                }
                VirtualKeyPair::Rs256(mut boxed) => {
                    let signature: rsa::pkcs1v15::Signature = boxed.as_mut().0.sign(payload);
                    Ok((-257, rsa::signature::SignatureEncoding::to_vec(&signature)))
                }
            }
        } else {
            warn!("Using TPM singing, even though the configuration is set to virtual.");
            let mut tpm = Tpm::new().expect("Failed to initialize TPM hardware backend. Are you sure you have TPM? You can check this with the command `ls /dev/tpm*`. If this returns nothing, either you don't have TPM or it isn't functioning properly. You might want to switch to virtual cryptography.");
            tpm.sign_payload(crypto_pair, payload)
        }
    }
}
