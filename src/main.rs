use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::str;

// ChaCha20 stream cipher and helpers
use chacha20::ChaCha20;
use cipher::{KeyIvInit, StreamCipher};
use cipher::generic_array::GenericArray;

// Random number generation
use rand::RngCore;

// Argon2 for password-based key derivation
use argon2::{Argon2, Algorithm, Params, Version};

// Import prompt_password
use rpassword::prompt_password;

/// --------------------------------------------------------------------------
/// Custom Argon2 parameters (you can tweak these before compile).
/// --------------------------------------------------------------------------
const ARGON2_MEMORY_KIB: u32 = 64 * 1024;  // 64 MiB of RAM for hashing
const ARGON2_TIME_COST: u32 = 4;          // Number of passes
const ARGON2_PARALLELISM: u32 = 1;        // Single-threaded (increase if desired)

/// We'll use a 12-byte nonce for regular ChaCha20 (RFC 8439 style).
const NONCE_SIZE: usize = 12;

/// Magic bytes to indicate an encrypted file (8 bytes). Feel free to change.
const MAGIC: &[u8; 8] = b"TCRYPT01";

/// Simple helper to convert bytes into a hex string.
fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn main() -> io::Result<()> {
    // 1. Parse CLI for filename
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <filename>", args[0]);
        std::process::exit(1);
    }
    let filename = &args[1];

    // 2. Read file contents first, so we know if it's encrypted or not
    let file_data = fs::read(filename)?;
    let is_encrypted = file_data.len() >= MAGIC.len() && &file_data[0..MAGIC.len()] == MAGIC;

    // 3. Prompt for password(s)
    let password = if is_encrypted {
        // If the file is encrypted, just ask for the password once.
        prompt_password("Password: ")
            .expect("Failed to read password from stdin")
    } else {
        // If we're encrypting, ask for password twice for confirmation.
        let p1 = prompt_password("New Password: ")
            .expect("Failed to read password from stdin");
        let p2 = prompt_password("Confirm Password: ")
            .expect("Failed to read password from stdin");

        if p1 != p2 {
            eprintln!("Passwords did not match. Exiting.");
            std::process::exit(1);
        }
        p1
    };

    // 4. Prepare custom Argon2 instance
    let argon2_params = Params::new(
        ARGON2_MEMORY_KIB,   // memory cost in KiB
        ARGON2_TIME_COST,    // time cost
        ARGON2_PARALLELISM,  // parallelism
        None,                // output_size (None by default)
    ).expect("Invalid Argon2 parameters");

    let argon2 = Argon2::new(
        Algorithm::Argon2id, // Argon2id is recommended
        Version::V0x13,
        argon2_params,
    );

    // 5. Prepare final data to overwrite
    let final_data = if is_encrypted {
        // DECRYPT
        // Layout: [ MAGIC(8) | SALT(16) | NONCE(12) | CIPHERTEXT(...) ]
        let needed_len = MAGIC.len() + 16 + NONCE_SIZE;
        if file_data.len() < needed_len {
            eprintln!("File too small to contain necessary encryption metadata.");
            std::process::exit(1);
        }

        let salt_bytes = &file_data[MAGIC.len()..MAGIC.len() + 16];
        let nonce_bytes = &file_data[MAGIC.len() + 16..MAGIC.len() + 16 + NONCE_SIZE];
        let ciphertext = &file_data[MAGIC.len() + 16 + NONCE_SIZE..];

        // Derive a 256-bit key (32 bytes) from the password & salt
        let mut key = [0u8; 32];
        argon2
            .hash_password_into(password.as_bytes(), salt_bytes, &mut key)
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "Argon2 failure"))?;

        let key_array = GenericArray::from_slice(&key);
        let nonce_array = GenericArray::from_slice(nonce_bytes);
        let mut cipher = ChaCha20::new(key_array, nonce_array);

        let mut decrypted_data = ciphertext.to_vec();
        cipher.apply_keystream(&mut decrypted_data);

        decrypted_data
    } else {
        // ENCRYPT
        // Layout: [ MAGIC(8) | SALT(16) | NONCE(12) | CIPHERTEXT(...) ]

        let mut rng = rand::thread_rng();

        // Generate random salt
        let mut salt = [0u8; 16];
        rng.fill_bytes(&mut salt);

        // Derive a 256-bit key from the password
        let mut key = [0u8; 32];
        argon2
            .hash_password_into(password.as_bytes(), &salt, &mut key)
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "Argon2 failure"))?;

        // Generate random nonce
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        rng.fill_bytes(&mut nonce_bytes);

        let key_array = GenericArray::from_slice(&key);
        let nonce_array = GenericArray::from_slice(&nonce_bytes);
        let mut cipher = ChaCha20::new(key_array, nonce_array);

        let mut encrypted_data = file_data.clone();
        cipher.apply_keystream(&mut encrypted_data);

        let mut output = Vec::new();
        output.extend_from_slice(MAGIC);
        output.extend_from_slice(&salt);
        output.extend_from_slice(&nonce_bytes);
        output.extend_from_slice(&encrypted_data);

        // For debugging, now we ONLY append the current magic/salt/nonce to data.txt on ENCRYPT
        log_debug_info(MAGIC, &salt, &nonce_bytes)?;

        output
    };

    // 6. Overwrite file atomically
    atomic_overwrite_file(filename, &final_data)?;

    Ok(())
}

/// Atomically overwrite a file by writing to a temp file and renaming.
///
/// This reduces the risk of partial or corrupted writes on crash.
fn atomic_overwrite_file(original_path: &str, data: &[u8]) -> io::Result<()> {
    let path = Path::new(original_path);
    let tmp_path = path.with_file_name(format!(
        "{}.tmp",
        path.file_name().unwrap().to_string_lossy()
    ));

    {
        let mut tmp_file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp_path)?;
        tmp_file.write_all(data)?;
        tmp_file.flush()?;
        tmp_file.sync_all()?;
    }

    fs::rename(tmp_path, path)?;
    Ok(())
}

/// Appends operation info to "data.txt" only for ENCRYPT.
fn log_debug_info(magic: &[u8], salt: &[u8], nonce: &[u8]) -> io::Result<()> {
    let mut debug_file = OpenOptions::new()
        .write(true)
        .create(true)
        .append(true)
        .open("data.txt")?;

    let magic_str = str::from_utf8(magic).unwrap_or("<invalid-utf8>");
    let salt_hex = to_hex(salt);
    let nonce_hex = to_hex(nonce);

    writeln!(
        debug_file,
        "ENCRYPT => Magic: {m}, Salt: {s}, Nonce: {n}",
        m = magic_str,
        s = salt_hex,
        n = nonce_hex
    )?;

    Ok(())
}

