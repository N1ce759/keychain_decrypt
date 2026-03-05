mod crypto;
mod error;
mod parser;

use crate::crypto::*;
use crate::error::KeychainError;
use crate::parser::*;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::process;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!(
            "Usage: {} --keychain <path> --password <password>",
            args[0]
        );
        eprintln!("Example: {} --keychain login.keychain-db --password mypass", args[0]);
        process::exit(1);
    }

    let mut keychain_path = String::new();
    let mut password = String::new();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--keychain" => {
                i += 1;
                keychain_path = args.get(i).cloned().unwrap_or_default();
            }
            "--password" => {
                i += 1;
                password = args.get(i).cloned().unwrap_or_default();
            }
            _ => {
                eprintln!("Unknown argument: {}", args[i]);
                process::exit(1);
            }
        }
        i += 1;
    }

    if keychain_path.is_empty() || password.is_empty() {
        eprintln!("Both --keychain and --password are required.");
        process::exit(1);
    }

    match decrypt_chrome_safe_storage(&keychain_path, &password) {
        Ok(plaintext) => {
            println!("[+] Chrome Safe Storage password (plaintext):");
            // Try to display as UTF-8 string
            match String::from_utf8(plaintext.clone()) {
                Ok(s) => println!("    {}", s),
                Err(_) => println!("    (hex) {}", hex::encode(&plaintext)),
            }
            println!("[+] Hex: {}", hex::encode(&plaintext));
            println!("[+] Length: {} bytes", plaintext.len());
        }
        Err(e) => {
            eprintln!("[!] Error: {}", e);
            process::exit(1);
        }
    }
}

/// High-level function: decrypt the Chrome Safe Storage entry from a keychain file.
fn decrypt_chrome_safe_storage(
    keychain_path: &str,
    password: &str,
) -> Result<Vec<u8>, KeychainError> {
    // 1. Read the keychain file
    let data = fs::read(keychain_path)?;
    println!("[*] Read keychain file: {} bytes", data.len());

    // 2. Parse the file header
    let header = parse_header(&data)?;
    println!(
        "[*] Keychain signature: {:?}, schema at 0x{:x}",
        std::str::from_utf8(&header.signature).unwrap_or("????"),
        header.schema_offset
    );

    // 3. Parse the schema and table offsets
    let (_schema, table_offsets) = parse_schema(&data, header.schema_offset as usize)?;
    println!("[*] Found {} tables", table_offsets.len());

    // 4. Build table ID → offset map
    let table_map = build_table_map(&data, &table_offsets)?;
    println!("[*] Built table map ({} entries)", table_map.len());

    // 5. Get metadata (DBBlob) table offset
    let metadata_offset = table_map
        .get(&CSSM_DL_DB_RECORD_METADATA)
        .ok_or(KeychainError::TableNotFound(CSSM_DL_DB_RECORD_METADATA))?;

    // 6. Parse DBBlob and derive master key
    let db_blob = parse_db_blob(&data, *metadata_offset)?;
    println!(
        "[*] DBBlob: magic=0x{:08X}, salt={}, iv={}",
        db_blob.magic,
        hex::encode(&db_blob.salt),
        hex::encode(&db_blob.iv)
    );

    let master_key = derive_master_key(password.as_bytes(), &db_blob.salt);
    println!("[*] Derived master key (PBKDF2): {}", hex::encode(&master_key));

    // 7. Decrypt the DB key (wrapping key)
    let db_blob_ct = get_db_blob_ciphertext(&data, *metadata_offset, &db_blob)?;
    let db_key = decrypt_db_key(&master_key, &db_blob.iv, &db_blob_ct)?;
    println!("[*] Decrypted DB key: {}", hex::encode(&db_key));

    // 8. Get symmetric key table and decrypt all key blobs
    let symkey_offset = table_map
        .get(&CSSM_DL_DB_RECORD_SYMMETRIC_KEY)
        .ok_or(KeychainError::TableNotFound(CSSM_DL_DB_RECORD_SYMMETRIC_KEY))?;

    let symkey_records = get_record_offsets(&data, *symkey_offset)?;
    println!("[*] Found {} symmetric key records", symkey_records.len());

    // Build key_list: ssgp_label (first 20 bytes) → decrypted record key
    let mut key_list: HashMap<Vec<u8>, [u8; KEYLEN]> = HashMap::new();

    for &roff in &symkey_records {
        match parse_key_blob_record(&data, *symkey_offset, roff)? {
            Some((label, ciphertext, iv)) => {
                match decrypt_key_blob(&db_key, &iv, &ciphertext) {
                    Ok(record_key) => {
                        key_list.insert(label[..20].to_vec(), record_key);
                    }
                    Err(e) => {
                        eprintln!("[!]   KeyBlob decrypt failed: {}", e);
                    }
                }
            }
            None => {}
        }
    }
    println!("[*] Decrypted {} key blobs", key_list.len());

    // 9. Find the Chrome Safe Storage generic password entry
    let genp_offset = table_map
        .get(&CSSM_DL_DB_RECORD_GENERIC_PASSWORD)
        .ok_or(KeychainError::TableNotFound(CSSM_DL_DB_RECORD_GENERIC_PASSWORD))?;

    let entries = find_generic_password_by_service(&data, *genp_offset, "Chrome Safe Storage")?;
    if entries.is_empty() {
        return Err(KeychainError::RecordNotFound(
            "Chrome Safe Storage".to_string(),
        ));
    }
    println!(
        "[*] Found {} 'Chrome Safe Storage' entries",
        entries.len()
    );

    // 10. Decrypt the SSGP data for each matching entry
    for entry in &entries {
        println!(
            "[*] Entry: service={:?}, account={:?}, print_name={:?}",
            entry.service, entry.account, entry.print_name
        );

        if entry.ssgp_data.len() < 28 {
            eprintln!("[!]   SSGP data too short, skipping");
            continue;
        }

        let (_label, ssgp_iv, ssgp_ciphertext) = parse_ssgp(&entry.ssgp_data)?;

        // The match key is the first 20 bytes of ssgp_data: "ssgp"(4) + label(16)
        // This matches how key_list keys are stored from parse_key_blob_record
        let match_key = &entry.ssgp_data[..20];

        println!(
            "[*]   SSGP match_key={}, iv={}, ct_len={}",
            hex::encode(match_key),
            hex::encode(&ssgp_iv),
            ssgp_ciphertext.len()
        );

        // Look up the matching record key by the 20-byte match key
        let record_key = key_list
            .get(match_key)
            .ok_or_else(|| {
                KeychainError::RecordNotFound(format!(
                    "no key blob matching SSGP key {}",
                    hex::encode(match_key)
                ))
            })?;

        // Decrypt the password
        let plaintext = decrypt_ssgp(record_key, &ssgp_iv, ssgp_ciphertext)?;
        return Ok(plaintext);
    }

    Err(KeychainError::RecordNotFound(
        "failed to decrypt any Chrome Safe Storage entry".to_string(),
    ))
}
