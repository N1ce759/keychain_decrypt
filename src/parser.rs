#![allow(dead_code)]

use crate::crypto::{BLOB_MAGIC, BLOCKSIZE, SSGP_MAGIC};
use crate::error::KeychainError;
use std::collections::HashMap;

// ──────────────────────────────────────────────
//  Constants
// ──────────────────────────────────────────────

pub const KEYCHAIN_SIGNATURE: &[u8; 4] = b"kych";
pub const APPL_DB_HEADER_SIZE: usize = 20;
pub const TABLE_HEADER_SIZE: usize = 28;

/// Record type IDs (big-endian u32)
pub const CSSM_DL_DB_RECORD_GENERIC_PASSWORD: u32 = 0x8000_0000;
pub const CSSM_DL_DB_RECORD_INTERNET_PASSWORD: u32 = 0x8000_0002;
pub const CSSM_DL_DB_RECORD_APPLESHARE_PASSWORD: u32 = 0x8000_0001;
pub const CSSM_DL_DB_RECORD_X509_CERTIFICATE: u32 = 0x8000_1000;
pub const CSSM_DL_DB_RECORD_METADATA: u32 = 0x8000_8000;
pub const CSSM_DL_DB_RECORD_SYMMETRIC_KEY: u32 = 0x0000_0011;
pub const CSSM_DL_DB_RECORD_PRIVATE_KEY: u32 = 0x0000_0010;
pub const CSSM_DL_DB_RECORD_PUBLIC_KEY: u32 = 0x0000_000F;

/// SSGP (Secure Storage Group Password) marker - identifies encrypted password blobs
pub const SECURE_STORAGE_GROUP: &[u8; 4] = b"ssgp";

// ──────────────────────────────────────────────
//  Data Structures
// ──────────────────────────────────────────────

/// Apple Database file header (20 bytes, big-endian)
#[derive(Debug)]
pub struct ApplDbHeader {
    pub signature: [u8; 4],
    pub version: u32,
    pub header_size: u32,
    pub schema_offset: u32,
    pub auth_offset: u32,
}

/// Database schema header
#[derive(Debug)]
pub struct ApplDbSchema {
    pub schema_size: u32,
    pub table_count: u32,
}

/// Table header (28 bytes, big-endian)
#[derive(Debug)]
pub struct TableHeader {
    pub table_size: u32,
    pub table_id: u32,
    pub record_count: u32,
    pub records: u32,
    pub indexes_offset: u32,
    pub free_list_head: u32,
    pub record_numbers_count: u32,
}

/// DBBlob - contains the encrypted wrapping key and PBKDF2 parameters
#[derive(Debug)]
pub struct DbBlob {
    pub magic: u32,
    pub version: u32,
    pub start_crypto_blob: u32,
    pub total_length: u32,
    pub random_signature: [u8; 16],
    pub sequence: u32,
    pub idle_timeout: u32,
    pub lock_on_sleep: u32,
    pub salt: [u8; 20],
    pub iv: [u8; 8],
    pub blob_signature: [u8; 20],
}

/// KeyBlob header - wraps a symmetric key record's encrypted data
#[derive(Debug)]
pub struct KeyBlobHeader {
    pub magic: u32,
    pub version: u32,
    pub start_crypto_blob: u32,
    pub total_length: u32,
    pub iv: [u8; 8],
}

/// SSGP header - precedes the per-item encrypted password data
#[derive(Debug)]
pub struct SsgpHeader {
    pub magic: [u8; 4],
    pub label: [u8; 16],
    pub iv: [u8; 8],
}

/// Generic Password record header
/// Each field (after record_size, record_number) is an offset to the attribute's
/// length-value pair within the record, or 0 if the attribute is absent.
/// The LSB is a flag; actual offset = field_value & 0xFFFFFFFE.
#[derive(Debug)]
pub struct GenericPwHeader {
    pub record_size: u32,
    pub record_number: u32,
    pub unknown2: u32,
    pub unknown3: u32,
    pub ssgp_area: u32,
    pub unknown5: u32,
    pub creation_date: u32,
    pub mod_date: u32,
    pub description: u32,
    pub comment: u32,
    pub creator: u32,
    pub type_: u32,
    pub script_code: u32,
    pub print_name: u32,
    pub alias: u32,
    pub invisible: u32,
    pub negative: u32,
    pub custom_icon: u32,
    pub protected: u32,
    pub account: u32,
    pub service: u32,
    pub generic: u32,
}

/// KeyBlob record header for symmetric key table
#[derive(Debug)]
pub struct KeyBlobRecHeader {
    pub record_size: u32,
    pub record_count: u32,
    // followed by 0x7C bytes of padding/unknown data
}

pub const KEY_BLOB_REC_HEADER_SIZE: usize = 4 + 4 + 0x7C; // 132 bytes
pub const GENERIC_PW_HEADER_SIZE: usize = 22 * 4; // 22 u32 fields = 88 bytes

// ──────────────────────────────────────────────
//  Helper: Big-Endian Readers
// ──────────────────────────────────────────────

fn read_u32_be(data: &[u8], offset: usize) -> Result<u32, KeychainError> {
    if offset + 4 > data.len() {
        return Err(KeychainError::ParseError(format!(
            "read_u32_be out of bounds: offset={}, len={}",
            offset,
            data.len()
        )));
    }
    Ok(u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]))
}

fn read_bytes<const N: usize>(data: &[u8], offset: usize) -> Result<[u8; N], KeychainError> {
    if offset + N > data.len() {
        return Err(KeychainError::ParseError(format!(
            "read_bytes<{}> out of bounds: offset={}, len={}",
            N,
            offset,
            data.len()
        )));
    }
    let mut arr = [0u8; N];
    arr.copy_from_slice(&data[offset..offset + N]);
    Ok(arr)
}

// ──────────────────────────────────────────────
//  Parsers
// ──────────────────────────────────────────────

pub fn parse_header(data: &[u8]) -> Result<ApplDbHeader, KeychainError> {
    if data.len() < APPL_DB_HEADER_SIZE {
        return Err(KeychainError::ParseError("file too small for header".into()));
    }
    let header = ApplDbHeader {
        signature: read_bytes::<4>(data, 0)?,
        version: read_u32_be(data, 4)?,
        header_size: read_u32_be(data, 8)?,
        schema_offset: read_u32_be(data, 12)?,
        auth_offset: read_u32_be(data, 16)?,
    };
    if &header.signature != KEYCHAIN_SIGNATURE {
        return Err(KeychainError::InvalidSignature);
    }
    Ok(header)
}

pub fn parse_schema(data: &[u8], offset: usize) -> Result<(ApplDbSchema, Vec<u32>), KeychainError> {
    let schema = ApplDbSchema {
        schema_size: read_u32_be(data, offset)?,
        table_count: read_u32_be(data, offset + 4)?,
    };

    // Table offsets start after the header + schema header (schema is at schema_offset)
    // In the file: offsets are at APPL_DB_HEADER_SIZE + 8 (after schema_size + table_count)
    let base = APPL_DB_HEADER_SIZE + 8; // 20 + 8 = 28
    let mut table_offsets = Vec::with_capacity(schema.table_count as usize);
    for i in 0..schema.table_count as usize {
        let off = read_u32_be(data, base + i * 4)?;
        table_offsets.push(off);
    }

    Ok((schema, table_offsets))
}

pub fn parse_table_header(data: &[u8], abs_offset: usize) -> Result<TableHeader, KeychainError> {
    Ok(TableHeader {
        table_size: read_u32_be(data, abs_offset)?,
        table_id: read_u32_be(data, abs_offset + 4)?,
        record_count: read_u32_be(data, abs_offset + 8)?,
        records: read_u32_be(data, abs_offset + 12)?,
        indexes_offset: read_u32_be(data, abs_offset + 16)?,
        free_list_head: read_u32_be(data, abs_offset + 20)?,
        record_numbers_count: read_u32_be(data, abs_offset + 24)?,
    })
}

/// Build a mapping from table_id → table_offset (relative value from table_offsets list)
pub fn build_table_map(
    data: &[u8],
    table_offsets: &[u32],
) -> Result<HashMap<u32, u32>, KeychainError> {
    let mut map = HashMap::new();
    for &off in table_offsets {
        let abs = APPL_DB_HEADER_SIZE + off as usize;
        let th = parse_table_header(data, abs)?;
        map.insert(th.table_id, off);
    }
    Ok(map)
}

/// Get list of valid record offsets within a table.
///
/// Returns relative record offsets (relative to the table start in the schema).
pub fn get_record_offsets(
    data: &[u8],
    table_offset: u32,
) -> Result<Vec<u32>, KeychainError> {
    let abs = APPL_DB_HEADER_SIZE + table_offset as usize;
    let th = parse_table_header(data, abs)?;

    let record_list_base = abs + TABLE_HEADER_SIZE;
    let mut records = Vec::new();
    let mut count = 0u32;
    let mut idx = 0u32;

    while count < th.record_count {
        let roff_pos = record_list_base + idx as usize * 4;
        if roff_pos + 4 > data.len() {
            break;
        }
        let record_offset = read_u32_be(data, roff_pos)?;
        if record_offset != 0 && record_offset % 4 == 0 {
            records.push(record_offset);
            count += 1;
        }
        idx += 1;
        // Safety: avoid infinite loop
        if idx > th.record_numbers_count + th.record_count + 1000 {
            break;
        }
    }

    Ok(records)
}

// ──────────────────────────────────────────────
//  DBBlob Parsing
// ──────────────────────────────────────────────

/// Parse the DBBlob from the metadata table.
///
/// The DBBlob is located at: APPL_DB_HEADER_SIZE + metadata_table_offset + 0x38
pub fn parse_db_blob(data: &[u8], metadata_table_offset: u32) -> Result<DbBlob, KeychainError> {
    let base = APPL_DB_HEADER_SIZE + metadata_table_offset as usize + 0x38;

    let magic = read_u32_be(data, base)?;
    if magic != BLOB_MAGIC {
        return Err(KeychainError::InvalidBlobMagic(magic));
    }

    Ok(DbBlob {
        magic,
        version: read_u32_be(data, base + 4)?,
        start_crypto_blob: read_u32_be(data, base + 8)?,
        total_length: read_u32_be(data, base + 12)?,
        random_signature: read_bytes::<16>(data, base + 16)?,
        sequence: read_u32_be(data, base + 32)?,
        idle_timeout: read_u32_be(data, base + 36)?,
        lock_on_sleep: read_u32_be(data, base + 40)?,
        salt: read_bytes::<20>(data, base + 44)?,
        iv: read_bytes::<8>(data, base + 64)?,
        blob_signature: read_bytes::<20>(data, base + 72)?,
    })
}

/// Extract the encrypted ciphertext from the DBBlob area.
pub fn get_db_blob_ciphertext(
    data: &[u8],
    metadata_table_offset: u32,
    db_blob: &DbBlob,
) -> Result<Vec<u8>, KeychainError> {
    let base = APPL_DB_HEADER_SIZE + metadata_table_offset as usize + 0x38;
    let start = base + db_blob.start_crypto_blob as usize;
    let end = base + db_blob.total_length as usize;
    if end > data.len() || start >= end {
        return Err(KeychainError::ParseError("DBBlob ciphertext out of bounds".into()));
    }
    Ok(data[start..end].to_vec())
}

// ──────────────────────────────────────────────
//  Symmetric Key (KeyBlob) Record Parsing
// ──────────────────────────────────────────────

/// Parse a symmetric key KeyBlob record.
///
/// Returns: (ssgp_label_20_bytes, ciphertext, iv, success)
pub fn parse_key_blob_record(
    data: &[u8],
    table_offset: u32,
    record_offset: u32,
) -> Result<Option<(Vec<u8>, Vec<u8>, [u8; BLOCKSIZE])>, KeychainError> {
    let base_addr = APPL_DB_HEADER_SIZE + table_offset as usize + record_offset as usize;

    // Read KeyBlobRecHeader: record_size (4) + record_count (4) + 0x7C padding
    let record_size = read_u32_be(data, base_addr)?;

    // The actual KeyBlob data starts after the 132-byte header
    let record_data_start = base_addr + KEY_BLOB_REC_HEADER_SIZE;
    let record_data_end = base_addr + record_size as usize;
    if record_data_end > data.len() || record_data_start >= record_data_end {
        return Ok(None);
    }
    let record_data = &data[record_data_start..record_data_end];

    // Parse KeyBlobHeader from the record data
    if record_data.len() < 24 {
        return Ok(None);
    }
    let kb_magic = read_u32_be(record_data, 0)?;
    let _kb_version = read_u32_be(record_data, 4)?;
    let kb_start = read_u32_be(record_data, 8)?;
    let kb_total = read_u32_be(record_data, 12)?;
    let kb_iv = read_bytes::<8>(record_data, 16)?;

    if kb_magic != BLOB_MAGIC {
        return Ok(None);
    }

    // Check for "ssgp" marker after the blob data
    let ssgp_offset = kb_total as usize + 8;
    if ssgp_offset + 4 > record_data.len() {
        return Ok(None);
    }
    if &record_data[ssgp_offset..ssgp_offset + 4] != SECURE_STORAGE_GROUP {
        return Ok(None);
    }

    // Extract ciphertext
    let cipher_len = kb_total as usize - kb_start as usize;
    if cipher_len % BLOCKSIZE != 0 || cipher_len == 0 {
        return Ok(None);
    }
    let ciphertext = record_data[kb_start as usize..kb_total as usize].to_vec();

    // Extract the 20-byte label (hash) used to match with SSGP records
    let label = record_data[ssgp_offset..ssgp_offset + 20].to_vec();

    Ok(Some((label, ciphertext, kb_iv)))
}

// ──────────────────────────────────────────────
//  Generic Password Record Parsing
// ──────────────────────────────────────────────

/// Read a length-value (LV) attribute from a record.
///
/// The attribute at `record_base + attr_offset` is: u32 length followed by `length` bytes of data.
fn read_lv(data: &[u8], record_base: usize, attr_offset: u32) -> Option<Vec<u8>> {
    let offset = (attr_offset & 0xFFFF_FFFE) as usize;
    if offset == 0 {
        return None;
    }
    let abs = record_base + offset;
    if abs + 4 > data.len() {
        return None;
    }
    let len = u32::from_be_bytes([data[abs], data[abs + 1], data[abs + 2], data[abs + 3]]) as usize;
    if len == 0 || abs + 4 + len > data.len() {
        return None;
    }
    Some(data[abs + 4..abs + 4 + len].to_vec())
}

/// Parse a generic password record header
pub fn parse_generic_pw_header(data: &[u8], abs_offset: usize) -> Result<GenericPwHeader, KeychainError> {
    Ok(GenericPwHeader {
        record_size: read_u32_be(data, abs_offset)?,
        record_number: read_u32_be(data, abs_offset + 4)?,
        unknown2: read_u32_be(data, abs_offset + 8)?,
        unknown3: read_u32_be(data, abs_offset + 12)?,
        ssgp_area: read_u32_be(data, abs_offset + 16)?,
        unknown5: read_u32_be(data, abs_offset + 20)?,
        creation_date: read_u32_be(data, abs_offset + 24)?,
        mod_date: read_u32_be(data, abs_offset + 28)?,
        description: read_u32_be(data, abs_offset + 32)?,
        comment: read_u32_be(data, abs_offset + 36)?,
        creator: read_u32_be(data, abs_offset + 40)?,
        type_: read_u32_be(data, abs_offset + 44)?,
        script_code: read_u32_be(data, abs_offset + 48)?,
        print_name: read_u32_be(data, abs_offset + 52)?,
        alias: read_u32_be(data, abs_offset + 56)?,
        invisible: read_u32_be(data, abs_offset + 60)?,
        negative: read_u32_be(data, abs_offset + 64)?,
        custom_icon: read_u32_be(data, abs_offset + 68)?,
        protected: read_u32_be(data, abs_offset + 72)?,
        account: read_u32_be(data, abs_offset + 76)?,
        service: read_u32_be(data, abs_offset + 80)?,
        generic: read_u32_be(data, abs_offset + 84)?,
    })
}

/// A parsed generic password entry with its attributes and SSGP data
#[derive(Debug)]
pub struct GenericPasswordEntry {
    pub print_name: Option<String>,
    pub service: Option<String>,
    pub account: Option<String>,
    pub ssgp_data: Vec<u8>, // raw SSGP blob (header + encrypted data)
}

/// Find a generic password record by service name.
///
/// Returns entries matching the given service name.
pub fn find_generic_password_by_service(
    data: &[u8],
    table_offset: u32,
    target_service: &str,
) -> Result<Vec<GenericPasswordEntry>, KeychainError> {
    let record_offsets = get_record_offsets(data, table_offset)?;
    let mut results = Vec::new();

    for &roff in &record_offsets {
        let abs = APPL_DB_HEADER_SIZE + table_offset as usize + roff as usize;
        if abs + GENERIC_PW_HEADER_SIZE > data.len() {
            continue;
        }

        let hdr = match parse_generic_pw_header(data, abs) {
            Ok(h) => h,
            Err(_) => continue,
        };

        // Read the service attribute
        let service_bytes = read_lv(data, abs, hdr.service);
        let service_str = service_bytes
            .as_ref()
            .and_then(|b| std::str::from_utf8(b).ok())
            .map(|s| s.trim_end_matches('\0').to_string());

        let print_name_bytes = read_lv(data, abs, hdr.print_name);
        let print_name = print_name_bytes
            .as_ref()
            .and_then(|b| std::str::from_utf8(b).ok())
            .map(|s| s.trim_end_matches('\0').to_string());

        let account_bytes = read_lv(data, abs, hdr.account);
        let account = account_bytes
            .as_ref()
            .and_then(|b| std::str::from_utf8(b).ok())
            .map(|s| s.trim_end_matches('\0').to_string());

        // Check if this is a match
        let matches = service_str
            .as_ref()
            .map(|s| s == target_service)
            .unwrap_or(false);

        if !matches {
            continue;
        }

        // Extract SSGP data area
        if hdr.ssgp_area == 0 {
            continue;
        }

        let ssgp_start = abs + GENERIC_PW_HEADER_SIZE;
        let ssgp_end = ssgp_start + hdr.ssgp_area as usize;
        if ssgp_end > data.len() {
            continue;
        }

        let ssgp_data = data[ssgp_start..ssgp_end].to_vec();

        results.push(GenericPasswordEntry {
            print_name,
            service: service_str,
            account,
            ssgp_data,
        });
    }

    Ok(results)
}

/// Parse an SSGP header from the SSGP data blob.
///
/// Returns (ssgp_label, ssgp_iv, ciphertext_after_header).
pub fn parse_ssgp(ssgp_data: &[u8]) -> Result<([u8; 16], [u8; BLOCKSIZE], &[u8]), KeychainError> {
    // SSGP: magic(4) + label(16) + iv(8) = 28 bytes header
    if ssgp_data.len() < 28 {
        return Err(KeychainError::ParseError("SSGP data too short".into()));
    }

    let magic = &ssgp_data[0..4];
    if magic != SSGP_MAGIC {
        return Err(KeychainError::ParseError(format!(
            "invalid SSGP magic: {:?}",
            magic
        )));
    }

    let label = read_bytes::<16>(ssgp_data, 4)?;
    let iv = read_bytes::<8>(ssgp_data, 20)?;
    let ciphertext = &ssgp_data[28..];

    Ok((label, iv, ciphertext))
}
