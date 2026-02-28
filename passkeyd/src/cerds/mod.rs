pub mod get;
pub mod make;

pub const ALGO_ES256: i32 = -7;
// pub const ALGO_EDDSA: i32 = -8; (isn't support by tpm)
pub const ALGO_RS256: i32 = -257;

// util function
use der::{Encode, Sequence, asn1::UintRef};

#[derive(Sequence)]
struct EcdsaSignature<'a> {
    pub r: UintRef<'a>,
    pub s: UintRef<'a>,
}
fn translate_es256_to_der(r_bytes: &[u8], s_bytes: &[u8]) -> Vec<u8> {
    let sig = EcdsaSignature {
        r: UintRef::new(&r_bytes).expect("invalid r"),
        s: UintRef::new(&s_bytes).expect("invalid s"),
    };
    sig.to_der().expect("DER-ASN.1 encoding failed")
}
