//! Errors of the TPM shell.

use std::fmt;

#[derive(Debug)]
pub enum Error {
    /// The TPM stack returned an error.
    Tss(tss_esapi::Error),
    /// No storage root key at the persistent handle.
    SrkMissing,
    /// The object at the SRK handle isn't a TCG ECC P-256 SRK (wrong template).
    NotAnSrk,
    /// The SRK's Name differs from the pinned one: the TPM was cleared or the key replaced.
    SrkMismatch,
    /// Data read from disk or from the TPM is malformed.
    Corrupt(&'static str),
    /// Filesystem error on broker state.
    Io(std::io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tss(e) => write!(f, "TPM error: {e}"),
            Self::SrkMissing => f.write_str("storage root key not present"),
            Self::NotAnSrk => f.write_str("object at the SRK handle is not a TCG ECC P-256 SRK"),
            Self::SrkMismatch => f.write_str("storage root key changed (TPM cleared?)"),
            Self::Corrupt(what) => write!(f, "corrupt {what}"),
            Self::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Tss(e) => Some(e),
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<tss_esapi::Error> for Error {
    fn from(e: tss_esapi::Error) -> Self {
        Self::Tss(e)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    /// Maps to the outcome the verified core turns into a CTAP status code.
    #[must_use]
    pub fn to_tpm_error(&self) -> passkey_tpm_core::tpm_iface::TpmError {
        use passkey_tpm_core::tpm_iface::TpmError;
        use tss_esapi::constants::response_code::Tss2ResponseCodeKind as Kind;
        match self {
            Self::SrkMissing | Self::SrkMismatch | Self::NotAnSrk => TpmError::Reset,
            Self::Tss(tss_esapi::Error::Tss2Error(rc)) => match rc.kind() {
                Some(Kind::Lockout) => TpmError::Lockout,
                Some(Kind::AuthFail | Kind::BadAuth) => TpmError::WrongPin,
                Some(
                    Kind::PolicyFail
                    | Kind::AuthUnavailable
                    | Kind::Integrity
                    | Kind::Value
                    | Kind::Handle,
                ) => TpmError::PolicyFailed,
                _ => TpmError::Unavailable,
            },
            // Malformed or foreign blobs behave like an unknown credential.
            Self::Corrupt(_) => TpmError::PolicyFailed,
            Self::Tss(tss_esapi::Error::WrapperError(_)) | Self::Io(_) => TpmError::Unavailable,
        }
    }
}
