use der::{Encode, Sequence, asn1::UintRef};
use passkeyd_abi::{config::Config, cryptography::CryptoBackend};

mod tpm;
mod r#virtual;

pub fn resolve_cryptography(confg: &Config) -> Box<dyn CryptoBackend> {
    if confg.use_tpm_cryptography {
        let tpm_backend = tpm::Tpm::new()
        .expect("Failed to initialize TPM hardware backend. Are you sure you have TPM? You can check this with the command `ls /dev/tpm*`. If this returns nothing, either you don't have TPM or it isn't functioning properly. You might want to switch to virtual cryptography.");
        Box::new(tpm_backend)
    } else {
        Box::new(r#virtual::Virtual)
    }
}

#[derive(Sequence)]
struct EcdsaSignature<'a> {
    pub r: UintRef<'a>,
    pub s: UintRef<'a>,
}
fn translate_es256_to_der(r_bytes: &[u8], s_bytes: &[u8]) -> Vec<u8> {
    let sig = EcdsaSignature {
        r: UintRef::new(r_bytes).expect("invalid r"),
        s: UintRef::new(s_bytes).expect("invalid s"),
    };
    sig.to_der().expect("DER-ASN.1 encoding failed")
}
