use p256::ecdsa::{SigningKey, VerifyingKey};
use rsa::rand_core::OsRng;

pub fn make_cerd() -> anyhow::Result<(SigningKey, VerifyingKey)> {
    let signing_key = SigningKey::random(&mut OsRng);
    let verifying_key = VerifyingKey::from(&signing_key);

    Ok((signing_key, verifying_key))
}
