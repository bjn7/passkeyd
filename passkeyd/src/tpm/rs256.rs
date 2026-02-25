use tss_esapi::{
    Context,
    attributes::ObjectAttributesBuilder,
    handles::KeyHandle,
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        key_bits::RsaKeyBits,
    },
    structures::{
        Auth, HashScheme, Private, Public, PublicBuilder, PublicKeyRsa, PublicRsaParametersBuilder,
        RsaExponent, RsaScheme, SymmetricDefinitionObject,
    },
};

pub fn make_cerd(
    ctx: &mut Context,
    srk_key_handle: &KeyHandle,
) -> anyhow::Result<(Private, Public)> {
    let rsa_params = PublicRsaParametersBuilder::new()
        .with_key_bits(RsaKeyBits::Rsa2048) //standard bit
        .with_exponent(RsaExponent::ZERO_EXPONENT)
        .with_scheme(RsaScheme::RsaSsa(HashScheme::new(HashingAlgorithm::Sha256)))
        .with_symmetric(SymmetricDefinitionObject::Null) //signing
        .with_restricted(false)
        .with_is_decryption_key(false)
        .with_is_signing_key(true)
        .build()
        .expect("failed to build rsa");

    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_restricted(false)
        .with_decrypt(false)
        .with_sign_encrypt(true)
        .build()
        .expect("failed to build attributes");

    let public_template = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Rsa)
        .with_rsa_parameters(rsa_params)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attributes)
        .with_rsa_unique_identifier(PublicKeyRsa::default())
        .build()
        .expect("failed to build public template");

    let create_result = ctx.create(
        *srk_key_handle,
        public_template,
        Some(Auth::default()),
        None,
        None,
        None,
    )?;
    Ok((create_result.out_private, create_result.out_public))
}
