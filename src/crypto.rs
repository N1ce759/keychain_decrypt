use crate::error::KeychainError;
use cbc::cipher::{BlockDecryptMut, KeyIvInit};
use pbkdf2::pbkdf2_hmac;
use sha1::Sha1;

/// 3DES-CBC decryptor type alias
type TdesEde3CbcDec = cbc::Decryptor<des::TdesEde3>;

/// Fixed IV used in the first pass of KeyBlob decryption (from Apple's wrapKeyCms.cpp)
pub const MAGIC_CMS_IV: [u8; 8] = [0x4a, 0xdd, 0xa2, 0x2c, 0x79, 0xe8, 0x21, 0x05];

/// SSGP magic identifier
pub const SSGP_MAGIC: &[u8; 4] = b"ssgp";

/// Triple-DES key length (24 bytes = 192 bits)
pub const KEYLEN: usize = 24;

/// 3DES block size
pub const BLOCKSIZE: usize = 8;

/// PBKDF2 iteration count used by Apple's keychain
pub const PBKDF2_ITERATIONS: u32 = 1000;

/// Blob magic: 0xFADE0711
pub const BLOB_MAGIC: u32 = 0xFADE_0711;

// ──────────────────────────────────────────────
//  Core Decryption Primitives
// ──────────────────────────────────────────────

/// Derive a 24-byte master key from the user password and salt using PBKDF2-HMAC-SHA1.
///
/// This is the first step in the keychain decryption chain.
pub fn derive_master_key(password: &[u8], salt: &[u8]) -> [u8; KEYLEN] {
    let mut dk = [0u8; KEYLEN];
    pbkdf2_hmac::<Sha1>(password, salt, PBKDF2_ITERATIONS, &mut dk);
    dk
}

/// Low-level 3DES-CBC decryption with PKCS7 unpadding.
///
/// - `key`: 24-byte 3DES key
/// - `iv`: 8-byte initialization vector
/// - `ciphertext`: data to decrypt (must be a multiple of 8 bytes)
///
/// Returns the unpadded plaintext, or an error if padding is invalid.
pub fn kc_decrypt(
    key: &[u8; KEYLEN],
    iv: &[u8; BLOCKSIZE],
    ciphertext: &[u8],
) -> Result<Vec<u8>, KeychainError> {
    if ciphertext.is_empty() {
        return Err(KeychainError::DecryptionFailed("empty ciphertext".into()));
    }
    if ciphertext.len() % BLOCKSIZE != 0 {
        return Err(KeychainError::DecryptionFailed(format!(
            "ciphertext length {} is not a multiple of block size {}",
            ciphertext.len(),
            BLOCKSIZE
        )));
    }

    let mut buf = ciphertext.to_vec();
    let decryptor = TdesEde3CbcDec::new(key.into(), iv.into());
    decryptor
        .decrypt_padded_mut::<cipher::block_padding::NoPadding>(&mut buf)
        .map_err(|_| KeychainError::DecryptionFailed("3DES-CBC decryption failed".into()))?;

    // Manual PKCS7 unpadding
    let pad = *buf.last().ok_or(KeychainError::BadPadding)? as usize;
    if pad == 0 || pad > BLOCKSIZE {
        return Err(KeychainError::BadPadding);
    }
    for &b in &buf[buf.len() - pad..] {
        if b as usize != pad {
            return Err(KeychainError::BadPadding);
        }
    }
    buf.truncate(buf.len() - pad);

    Ok(buf)
}

// ──────────────────────────────────────────────
//  Key Hierarchy Decryption
// ──────────────────────────────────────────────

/// Decrypt the DB key (wrapping key) from the DBBlob.
///
/// `master_key`: the 24-byte key derived via PBKDF2 from the user password.
/// `iv`: the 8-byte IV stored in the DBBlob structure.
/// `ciphertext`: the encrypted portion of the DBBlob (from startCryptoBlob to totalLength).
///
/// Returns the first 24 bytes of the decrypted plaintext as the DB key.
pub fn decrypt_db_key(
    master_key: &[u8; KEYLEN],
    iv: &[u8; BLOCKSIZE],
    ciphertext: &[u8],
) -> Result<[u8; KEYLEN], KeychainError> {
    let plain = kc_decrypt(master_key, iv, ciphertext)?;
    if plain.len() < KEYLEN {
        return Err(KeychainError::DecryptionFailed(format!(
            "decrypted DB key too short: {} bytes (expected >= {})",
            plain.len(),
            KEYLEN
        )));
    }
    let mut db_key = [0u8; KEYLEN];
    db_key.copy_from_slice(&plain[..KEYLEN]);
    Ok(db_key)
}

/// Decrypt a symmetric KeyBlob record to recover the 24-byte record key.
///
/// This is a two-pass decryption:
/// 1. Decrypt with `db_key` + `magicCmsIV` → intermediate plaintext
/// 2. Reverse the first 32 bytes of the intermediate
/// 3. Decrypt the reversed bytes with `db_key` + the KeyBlob's own `iv`
/// 4. Skip 4 header bytes → 24-byte record key
pub fn decrypt_key_blob(
    db_key: &[u8; KEYLEN],
    iv: &[u8; BLOCKSIZE],
    ciphertext: &[u8],
) -> Result<[u8; KEYLEN], KeychainError> {
    // First pass: decrypt with magicCmsIV
    let plain1 = kc_decrypt(db_key, &MAGIC_CMS_IV, ciphertext)?;

    if plain1.len() < 32 {
        return Err(KeychainError::DecryptionFailed(
            "first-pass KeyBlob decrypt too short".into(),
        ));
    }

    // Reverse the first 32 bytes
    let mut reversed = [0u8; 32];
    for i in 0..32 {
        reversed[i] = plain1[31 - i];
    }

    // Second pass: decrypt with the record's own IV
    let plain2 = kc_decrypt(db_key, iv, &reversed)?;

    // Skip 4 header bytes; the remaining 24 bytes are the record key
    if plain2.len() < 4 + KEYLEN {
        return Err(KeychainError::DecryptionFailed(format!(
            "second-pass KeyBlob decrypt too short: {} (expected >= {})",
            plain2.len(),
            4 + KEYLEN
        )));
    }

    let mut record_key = [0u8; KEYLEN];
    record_key.copy_from_slice(&plain2[4..4 + KEYLEN]);
    Ok(record_key)
}

/// Decrypt the SSGP (Secure Storage Group Password) data to recover the plaintext password.
///
/// `record_key`: the 24-byte key from `decrypt_key_blob`.
/// `ssgp_iv`: the 8-byte IV from the SSGP header.
/// `encrypted_data`: the ciphertext following the SSGP header.
pub fn decrypt_ssgp(
    record_key: &[u8; KEYLEN],
    ssgp_iv: &[u8; BLOCKSIZE],
    encrypted_data: &[u8],
) -> Result<Vec<u8>, KeychainError> {
    kc_decrypt(record_key, ssgp_iv, encrypted_data)
}
