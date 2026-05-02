use rsa::{
    RsaPrivateKey,
    pkcs1v15::{SigningKey, VerifyingKey},
    rand_core::OsRng,
    signature::Keypair,
};
use sha2::Sha256;

pub fn make_cerd() -> anyhow::Result<(SigningKey<Sha256>, VerifyingKey<Sha256>)> {
    let priv_key = RsaPrivateKey::new(&mut OsRng, 2048)
        .map_err(|e| anyhow::anyhow!("Failed to generate RSA key: {}", e))?;

    let signing_key = rsa::pkcs1v15::SigningKey::<Sha256>::new(priv_key);

    let verifying_key = signing_key.verifying_key();

    Ok((signing_key, verifying_key))
}
