use thiserror::Error;
pub mod ctaphid;
mod hid;
mod utils;

#[repr(u8)]
#[derive(Debug, Copy, Clone, Eq, PartialEq, Error)]
/// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#error-responses

#[allow(unused)]
pub enum CtapStatus {
    // Success
    #[error("Success")]
    Ok = 0x00,

    // CTAP2 CBOR / request errors
    #[error("Unexpected CBOR type")]
    CborUnexpectedType = 0x11,

    #[error("Invalid CBOR")]
    InvalidCbor = 0x12,

    #[error("Missing parameter")]
    MissingParameter = 0x14,

    #[error("Limit exceeded")]
    LimitExceeded = 0x15,

    #[error("Fingerprint database full")]
    FingerprintDatabaseFull = 0x17,

    #[error("Large blob storage full")]
    LargeBlobStorageFull = 0x18,

    #[error("Credential excluded")]
    CredentialExcluded = 0x19,

    // Processing / state
    #[error("Processing")]
    Processing = 0x21,

    #[error("Invalid credential")]
    InvalidCredential = 0x22,

    #[error("User action pending")]
    UserActionPending = 0x23,

    #[error("Operation pending")]
    OperationPending = 0x24,

    #[error("No operations")]
    NoOperations = 0x25,

    #[error("Unsupported algorithm")]
    UnsupportedAlgorithm = 0x26,

    #[error("Operation denied")]
    OperationDenied = 0x27,

    #[error("Key store full")]
    KeyStoreFull = 0x28,

    #[error("Unsupported option")]
    UnsupportedOption = 0x2B,

    #[error("Invalid option")]
    InvalidOption = 0x2C,

    #[error("Keepalive cancelled")]
    KeepaliveCancel = 0x2D,

    #[error("No credentials")]
    NoCredentials = 0x2E,

    #[error("User action timeout")]
    UserActionTimeout = 0x2F,

    #[error("Not allowed")]
    NotAllowed = 0x30,

    // PIN / UV errors
    #[error("PIN invalid")]
    PinInvalid = 0x31,

    #[error("PIN blocked")]
    PinBlocked = 0x32,

    #[error("PIN authentication invalid")]
    PinAuthInvalid = 0x33,

    #[error("PIN authentication blocked")]
    PinAuthBlocked = 0x34,

    #[error("PIN not set")]
    PinNotSet = 0x35,

    #[error("PinUvAuthToken required")]
    PuatRequired = 0x36,

    #[error("PIN policy violation")]
    PinPolicyViolation = 0x37,

    #[error("Request too large")]
    RequestTooLarge = 0x39,

    #[error("Action timeout")]
    ActionTimeout = 0x3A,

    #[error("User presence required")]
    UpRequired = 0x3B,

    #[error("User verification blocked")]
    UvBlocked = 0x3C,

    #[error("Integrity failure")]
    IntegrityFailure = 0x3D,

    #[error("Invalid subcommand")]
    InvalidSubcommand = 0x3E,

    #[error("User verification invalid")]
    UvInvalid = 0x3F,

    #[error("Unauthorized permission")]
    UnauthorizedPermission = 0x40,

    // Ranges / generic
    #[error("Other unspecified error")]
    Other = 0x7F,

    #[error("CTAP2 spec last error")]
    SpecLast = 0xDF,

    #[error("Extension specific error")]
    ExtensionFirst = 0xE0,

    #[error("Extension specific error")]
    ExtensionLast = 0xEF,

    #[error("Vendor specific error")]
    VendorFirst = 0xF0,

    #[error("Vendor specific error")]
    VendorLast = 0xFF,
}
