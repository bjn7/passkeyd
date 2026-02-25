use tss_esapi::{
    Context,
    attributes::ObjectAttributesBuilder,
    handles::KeyHandle,
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        ecc::EccCurve,
    },
    structures::{
        EccPoint, EccScheme, HashScheme, KeyDerivationFunctionScheme, Private, Public,
        PublicBuilder, PublicEccParametersBuilder, SymmetricDefinitionObject,
    },
};

use crate::tpm::get_pcr7_policy;

pub fn make_cerd(
    ctx: &mut Context,
    srk_key_handle: &KeyHandle,
) -> anyhow::Result<(Private, Public)> {
    let ecc_params = PublicEccParametersBuilder::new()
        .with_curve(EccCurve::NistP256)
        .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
        .with_ecc_scheme(EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256)))
        .with_symmetric(SymmetricDefinitionObject::Null) //signing
        .with_restricted(false)
        .with_is_decryption_key(false)
        .with_is_signing_key(true)
        .build()
        .expect("failed to build ecc");

    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(false)
        .with_restricted(false)
        .with_decrypt(false)
        .with_sign_encrypt(true)
        .build()
        .expect("failed to build attributes");

    let public_template = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_ecc_parameters(ecc_params)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attributes)
        .with_ecc_unique_identifier(EccPoint::default())
        .with_auth_policy(get_pcr7_policy(ctx)?)
        .build()
        .expect("failed to build public template");

    let create_result = ctx.create(*srk_key_handle, public_template, None, None, None, None)?;
    Ok((create_result.out_private, create_result.out_public))
}
