use std::fmt;

#[derive(Debug)]
pub enum KeychainError {
    Io(std::io::Error),
    InvalidSignature,
    InvalidBlobMagic(u32),
    TableNotFound(u32),
    RecordNotFound(String),
    BadPadding,
    DecryptionFailed(String),
    ParseError(String),
}

impl fmt::Display for KeychainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "IO error: {}", e),
            Self::InvalidSignature => write!(f, "Invalid keychain signature (expected 'kych')"),
            Self::InvalidBlobMagic(m) => write!(f, "Invalid blob magic: 0x{:08X}", m),
            Self::TableNotFound(id) => write!(f, "Table 0x{:08X} not found", id),
            Self::RecordNotFound(s) => write!(f, "Record not found: {}", s),
            Self::BadPadding => write!(f, "Bad PKCS7 padding (wrong password?)"),
            Self::DecryptionFailed(s) => write!(f, "Decryption failed: {}", s),
            Self::ParseError(s) => write!(f, "Parse error: {}", s),
        }
    }
}

impl std::error::Error for KeychainError {}

impl From<std::io::Error> for KeychainError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
