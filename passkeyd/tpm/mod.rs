use anyhow::Ok;
use log::debug;
use sha2::Sha256;
use std::str::FromStr;
use tss_esapi::{
    Context, TctiNameConf,
    attributes::ObjectAttributesBuilder,
    constants::{
        SessionType,
        tss::{TPM2_RH_NULL, TPM2_ST_HASHCHECK},
    },
    handles::{KeyHandle, ObjectHandle, SessionHandle},
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm, SymmetricMode},
        ecc::EccCurve,
        key_bits::AesKeyBits,
        resource_handles::Hierarchy,
        session_handles::{AuthSession},
    },
    structures::{
        self, Auth, Digest, EccPoint, EccScheme, HashcheckTicket, KeyDerivationFunctionScheme,
        PcrSelectionListBuilder, PcrSlot, Private, Public, PublicBuilder,
        PublicEccParametersBuilder, Signature, SignatureScheme, SymmetricDefinition,
        SymmetricDefinitionObject,
    },
    tss2_esys::TPMT_TK_HASHCHECK,
};

pub fn initialize_tpm_with_session() -> anyhow::Result<Context> {
    let mut ctx = initialize_tpm()?;
    debug!("TPM has been initialized");
    initialize_pass_session(&mut ctx);
    Ok(ctx)
}

fn initialize_tpm() -> anyhow::Result<Context> {
    let tcti = TctiNameConf::from_str("device:/dev/tpmrm0")?;
    let mut ctx = Context::new(tcti)?;
    ctx.startup(tss_esapi::constants::StartupType::Clear)?;
    Ok(ctx)
}

fn initialize_pass_session(ctx: &mut Context) {
    debug!("TPM session set to password.");
    ctx.set_sessions((Some(AuthSession::Password), None, None));
}

fn initialize_policy_session(ctx: &mut Context) -> anyhow::Result<()> {
    ctx.set_sessions((None, None, None));
    let session_handle = ctx
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Policy,
            SymmetricDefinition::Aes {
                key_bits: AesKeyBits::Aes128,
                mode: SymmetricMode::Cfb,
            },
            HashingAlgorithm::Sha256,
        )?
        .unwrap(); //can fail in out of sessions case, which ofc is rare.

    // binding to a secure boot
    let pcr_selection = PcrSelectionListBuilder::new()
        .with_selection(HashingAlgorithm::Sha256, &[PcrSlot::Slot7])
        .build()?;
    ctx.policy_pcr(session_handle.try_into()?, Digest::default(), pcr_selection)?;
    ctx.set_sessions((Some(session_handle), None, None));
    debug!("TPM session set to PCR 7 policy.");
    Ok(())
}

fn get_pcr7_policy(ctx: &mut Context) -> anyhow::Result<Digest> {
    let current_session = ctx.sessions();
    ctx.set_sessions((None, None, None));
    let session_handle = ctx
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Trial,
            SymmetricDefinition::Aes {
                key_bits: AesKeyBits::Aes128,
                mode: SymmetricMode::Cfb,
            },
            HashingAlgorithm::Sha256,
        )?
        .unwrap();

    // binding to a secure boot
    let pcr_selection = PcrSelectionListBuilder::new()
        .with_selection(HashingAlgorithm::Sha256, &[PcrSlot::Slot7])
        .build()?;
    ctx.policy_pcr(session_handle.try_into()?, Digest::default(), pcr_selection)?;
    let p = ctx.policy_get_digest(session_handle.try_into()?)?;
    ctx.flush_context(ObjectHandle::from(SessionHandle::from(session_handle)))?;
    ctx.set_sessions(current_session);
    Ok(p)
}

pub fn create_primary_key_handle(ctx: &mut Context) -> anyhow::Result<KeyHandle> {
    let ecc_params = PublicEccParametersBuilder::new()
        .with_curve(EccCurve::NistP256)
        .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
        .with_ecc_scheme(EccScheme::Null)
        .with_symmetric(SymmetricDefinitionObject::Aes {
            key_bits: AesKeyBits::Aes128,
            mode: SymmetricMode::Cfb,
        })
        .with_restricted(true)
        .with_is_decryption_key(true)
        .with_is_signing_key(false)
        .build()
        .expect("failed to build ecc");

    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_restricted(true)
        .with_decrypt(true)
        .with_sign_encrypt(false)
        .build()
        .expect("failed to build attributes");

    let public_template = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_ecc_parameters(ecc_params)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attributes)
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
        .expect("failed to build public template");

    let srk_handle = ctx.create_primary(
        Hierarchy::Owner,
        public_template,
        Some(Auth::default()),
        None,
        None,
        None,
    )?;
    debug!("Storage root key handler created");
    Ok(srk_handle.key_handle)
}

pub fn sign(
    ctx: &mut Context,
    srk_handle: &KeyHandle,
    private_key: Private,
    public_key: Public,
    data_to_sing: &[u8],
) -> anyhow::Result<Signature> {
    use sha2::Digest;
    let key_handle = ctx.load(*srk_handle, private_key, public_key)?;
    initialize_policy_session(ctx)?;

    let mut hasher = Sha256::new();
    hasher.update(&data_to_sing);
    let digest = structures::Digest::try_from(hasher.finalize().as_slice())?;

    let mut ticket = TPMT_TK_HASHCHECK::default();
    ticket.tag = TPM2_ST_HASHCHECK;
    ticket.hierarchy = TPM2_RH_NULL;

    let validation = HashcheckTicket::try_from(ticket)?;
    
    ctx.sign(key_handle, digest, SignatureScheme::Null, validation)
        .map_err(|e| e.into())
}

pub mod es256;
pub mod rs256;
