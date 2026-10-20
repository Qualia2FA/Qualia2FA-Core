// Copyright (C) 2026 Qualia2FA contributors
//
// This library is free software; you can redistribute it and/or modify it under
// the terms of the GNU Lesser General Public License as published by the Free
// Software Foundation; either version 3 of the License, or (at your option) any
// later version.
//
// This library is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
// details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this library; if not, see <https://www.gnu.org/licenses/>.

//! Opening an encrypted JSON export.
//!
//! # Two stages, and why the distinction is visible to the user
//!
//! The password does **not** decrypt the database. It derives a key that decrypts a **slot**,
//! which holds the master key; the master key decrypts the database. Two different things can
//! therefore go wrong, and they mean different things:
//!
//! - every password slot fails to authenticate: the password is wrong (or a slot was modified) -
//!   [`Error::ImportWrongPassword`];
//! - a slot opened but the database does not: the password was accepted, so the file is damaged
//!   or was modified after it was written - [`Error::ImportCorrupted`].
//!
//! A reader that merged the two would tell a user with the right password to try again, and would
//! tell a user with a damaged file that their password is wrong.
//!
//! # Every number that decides a cost is bounded before it is used
//!
//! The cost parameters come from the file, and the derivation they drive allocates memory
//! proportional to them. A file that asks for a gigabyte of scrypt memory must be refused
//! **before** the derivation starts, which is what [`Limits`] does; the reference implementation
//! does not bound them (its own check on the cost parameter only applies when the block size is
//! one), so this is the reader's job rather than a missing detail of the format.
//!
//! # Only password slots can be opened
//!
//! A slot is one of three kinds: one unlocked by a password, one by the platform key store, and
//! one by a biometric prompt. This library has no key store and no prompt - it reads a file - so
//! only password slots are tried, and an export that has none says so instead of reporting a
//! wrong password it never had a chance to check.

use aes_gcm::aead::{AeadInOut, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use secrecy::zeroize::Zeroize;
use tinyjson::JsonValue;

use crate::{Error, Result};

/// The slot kind that a password opens.
const SLOT_PASSWORD: u64 = 1;

/// The length of the AES-256-GCM nonce, in bytes.
const NONCE_LEN: usize = 12;

/// The length of the AES-256-GCM tag, in bytes.
const TAG_LEN: usize = 16;

/// The length of the derived key, in bytes.
const KEY_LEN: usize = 32;

/// What this reader is willing to spend on one file.
///
/// The numbers are not the format's: they are what a real export uses (a cost parameter of 2^15
/// with a block size of 8, which is 32 MiB) with room to spare, so a file that exceeds them is
/// either damaged or built to make this reader work rather than to hold a vault.
struct Limits;

impl Limits {
    /// The largest cost parameter accepted, as its base-2 logarithm.
    const MAX_LOG_N: u8 = 20;
    /// The largest memory the derivation may ask for, in bytes.
    const MAX_MEMORY: u64 = 256 * 1024 * 1024;
    /// The largest block size accepted.
    const MAX_R: u32 = 32;
    /// The largest parallelisation accepted.
    const MAX_P: u32 = 8;
    /// The largest number of slots read.
    const MAX_SLOTS: usize = 16;
    /// The largest salt accepted, in bytes.
    const MAX_SALT: usize = 64;
}

/// Opens the database of an encrypted export.
///
/// `database` is the base64 ciphertext from the document, `header` its header object, and
/// `password` the UTF-8 bytes of the password (the derivation consumes bytes, and hashing text
/// would mean choosing a normalization the format does not specify).
///
/// # Errors
///
/// [`Error::ImportMalformed`] when the header or a slot is not shaped as the format says,
/// [`Error::ImportInvalidKdfParameters`] when a cost parameter is out of range,
/// [`Error::ImportEncryptionUnsupported`] when no slot can be opened with a password,
/// [`Error::ImportWrongPassword`] when every password slot fails, and [`Error::ImportCorrupted`]
/// when a slot opened but the database did not.
pub(crate) fn unlock(database: &str, header: &JsonValue, password: &[u8]) -> Result<JsonValue> {
    let header = header
        .get::<std::collections::HashMap<String, JsonValue>>()
        .ok_or(Error::ImportMalformed {
            reason: "the encrypted export has no header object",
        })?;
    let slots = header
        .get("slots")
        .and_then(JsonValue::get::<Vec<JsonValue>>)
        .ok_or(Error::ImportMalformed {
            reason: "the encrypted export has no key slots",
        })?;
    if slots.len() > Limits::MAX_SLOTS {
        return Err(Error::ImportEncryptionUnsupported {
            reason: "it has more key slots than this reader accepts",
        });
    }

    let ciphertext = decode_base64(database)?;
    let mut master: Option<[u8; KEY_LEN]> = None;
    let mut password_slots = 0_usize;

    for slot in slots {
        let Some(slot) = slot.get::<std::collections::HashMap<String, JsonValue>>() else {
            continue;
        };
        if slot.get("type").and_then(integer) != Some(SLOT_PASSWORD) {
            // A slot this library cannot open is not an error on its own: it is skipped, and
            // whether that leaves anything to try is decided after the loop.
            continue;
        }
        password_slots += 1;
        if let Some(key) = open_slot(slot, password)? {
            master = Some(key);
            break;
        }
    }

    if password_slots == 0 {
        return Err(Error::ImportEncryptionUnsupported {
            reason: "it has no slot a password can open",
        });
    }
    let Some(mut master) = master else {
        return Err(Error::ImportWrongPassword);
    };

    let opened = open_with_master(&master, header, &ciphertext);
    master.zeroize();
    let plaintext = opened.map_err(|_| Error::ImportCorrupted)?;

    decode_utf8_json(&plaintext)
}

/// Tries one password slot, returning the master key when it authenticates.
///
/// `Ok(None)` means this slot is not the one: the AEAD failed, which is what a wrong password
/// looks like. Only a slot that is **malformed** - a missing field, a nonce of the wrong length -
/// is an error, because that says the file is not what it claims to be rather than that the
/// password is different.
fn open_slot(
    slot: &std::collections::HashMap<String, JsonValue>,
    password: &[u8],
) -> Result<Option<[u8; KEY_LEN]>> {
    let cost = slot
        .get("n")
        .and_then(integer)
        .ok_or(malformed("a slot has no cost parameter"))?;
    let block_size = slot
        .get("r")
        .and_then(integer)
        .ok_or(malformed("a slot has no block size"))?;
    let parallelisation = slot
        .get("p")
        .and_then(integer)
        .ok_or(malformed("a slot has no parallelisation parameter"))?;
    let salt = decode_hex(
        slot.get("salt")
            .and_then(JsonValue::get::<String>)
            .ok_or(malformed("a slot has no salt"))?,
    )?;
    if salt.len() > Limits::MAX_SALT {
        return Err(Error::ImportInvalidKdfParameters {
            reason: "the salt is longer than this reader accepts",
        });
    }
    let params = kdf_parameters(cost, block_size, parallelisation)?;

    let encrypted = decode_hex(
        slot.get("key")
            .and_then(JsonValue::get::<String>)
            .ok_or(malformed("a slot has no encrypted key"))?,
    )?;
    let (nonce, tag) = split_cipher_params(slot.get("key_params"))?;

    let mut derived = [0_u8; KEY_LEN];
    scrypt::scrypt(password, &salt, &params, &mut derived).map_err(|_| {
        Error::ImportInvalidKdfParameters {
            reason: "the derivation parameters cannot produce a key of this length",
        }
    })?;
    // The format keeps the tag beside the ciphertext; the AEAD wants the two together, in its
    // own order - a ciphertext reaching it without its tag would authenticate as a shorter
    // message.
    let mut sealed = encrypted;
    sealed.extend_from_slice(&tag);

    let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(derived));
    // Decryption happens in place and truncates the buffer to the plaintext, so `sealed` holds
    // the key once this succeeds.
    let opened = cipher.decrypt_in_place(&Nonce::from(nonce), &[], &mut sealed);
    derived.zeroize();
    if opened.is_err() {
        // The only failure the AEAD reports is a failed authentication, which is what a wrong
        // password looks like from here.
        return Ok(None);
    }

    if sealed.len() != KEY_LEN {
        // The slot authenticated, so the password is right; what is inside it is simply not a
        // key. That is a damaged file, not a wrong password.
        return Err(Error::ImportCorrupted);
    }
    let mut key = [0_u8; KEY_LEN];
    key.copy_from_slice(&sealed);
    sealed.zeroize();
    Ok(Some(key))
}

/// Decrypts the database with the master key a slot produced.
fn open_with_master(
    master: &[u8; KEY_LEN],
    header: &std::collections::HashMap<String, JsonValue>,
    ciphertext: &[u8],
) -> core::result::Result<Vec<u8>, ()> {
    let (nonce, tag) = split_cipher_params(header.get("params")).map_err(|_| ())?;
    let mut buffer = ciphertext.to_vec();
    buffer.extend_from_slice(&tag);
    let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(*master));
    cipher
        .decrypt_in_place(&Nonce::from(nonce), &[], &mut buffer)
        .map_err(|_| ())?;
    Ok(buffer)
}

/// Reads the nonce and the tag of one encrypted section.
///
/// The format stores the tag beside the ciphertext rather than appended to it, so the callers put
/// the two back together - ciphertext first, tag last, which is the order the AEAD expects.
fn split_cipher_params(value: Option<&JsonValue>) -> Result<([u8; NONCE_LEN], [u8; TAG_LEN])> {
    let params = value
        .and_then(|value| value.get::<std::collections::HashMap<String, JsonValue>>())
        .ok_or(malformed("an encrypted section has no cipher parameters"))?;
    let nonce = decode_hex(
        params
            .get("nonce")
            .and_then(JsonValue::get::<String>)
            .ok_or(malformed("an encrypted section has no nonce"))?,
    )?;
    let tag = decode_hex(
        params
            .get("tag")
            .and_then(JsonValue::get::<String>)
            .ok_or(malformed("an encrypted section has no tag"))?,
    )?;
    let nonce: [u8; NONCE_LEN] = nonce
        .try_into()
        .map_err(|_| malformed("an encrypted section has a nonce of the wrong length"))?;
    let tag: [u8; TAG_LEN] = tag
        .try_into()
        .map_err(|_| malformed("an encrypted section has a tag of the wrong length"))?;
    Ok((nonce, tag))
}

/// Validates the cost parameters and builds the derivation parameters.
///
/// The cost is given as the number of iterations rather than as its logarithm, so it has to be a
/// power of two - anything else is not a parameter scrypt can take, and rounding it would make
/// this reader spend a different amount of work than the file asked for.
fn kdf_parameters(cost: u64, block_size: u64, parallelisation: u64) -> Result<scrypt::Params> {
    if !cost.is_power_of_two() {
        return Err(Error::ImportInvalidKdfParameters {
            reason: "the cost parameter is not a power of two",
        });
    }
    let log_n = cost.trailing_zeros();
    if log_n > u32::from(Limits::MAX_LOG_N) {
        return Err(Error::ImportInvalidKdfParameters {
            reason: "the cost parameter is higher than this reader accepts",
        });
    }
    let block_size = u32::try_from(block_size).map_err(|_| Error::ImportInvalidKdfParameters {
        reason: "the block size is out of range",
    })?;
    let parallelisation =
        u32::try_from(parallelisation).map_err(|_| Error::ImportInvalidKdfParameters {
            reason: "the parallelisation parameter is out of range",
        })?;
    if block_size == 0 || block_size > Limits::MAX_R {
        return Err(Error::ImportInvalidKdfParameters {
            reason: "the block size is out of range",
        });
    }
    if parallelisation == 0 || parallelisation > Limits::MAX_P {
        return Err(Error::ImportInvalidKdfParameters {
            reason: "the parallelisation parameter is out of range",
        });
    }
    // scrypt allocates about `128 * cost * block_size` bytes. This is the check that keeps a
    // crafted file from asking for a gigabyte, and it has to happen here rather than inside the
    // derivation, which would already have allocated.
    let memory = 128_u64
        .saturating_mul(cost)
        .saturating_mul(u64::from(block_size));
    if memory > Limits::MAX_MEMORY {
        return Err(Error::ImportInvalidKdfParameters {
            reason: "the derivation would need more memory than this reader allows",
        });
    }

    #[expect(
        clippy::cast_possible_truncation,
        reason = "the value is at most MAX_LOG_N, checked above"
    )]
    let log_n = log_n as u8;
    scrypt::Params::new(log_n, block_size, parallelisation).map_err(|_| {
        Error::ImportInvalidKdfParameters {
            reason: "the derivation parameters are not valid for scrypt",
        }
    })
}

/// Parses the decrypted database.
fn decode_utf8_json(plaintext: &[u8]) -> Result<JsonValue> {
    let text = core::str::from_utf8(plaintext).map_err(|_| Error::ImportCorrupted)?;
    text.parse().map_err(|_| Error::ImportCorrupted)
}

/// Decodes standard base64, which is what the format writes for the database.
///
/// The decoder itself is shared with the icon reader (see [`crate::import::decode_base64`]); this
/// wrapper only turns "not base64" into this module's error.
fn decode_base64(text: &str) -> Result<Vec<u8>> {
    crate::import::decode_base64(text)
        .ok_or_else(|| malformed("the encrypted database is not valid base64"))
}

/// Decodes hexadecimal text, upper or lower case.
fn decode_hex(text: &str) -> Result<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return Err(malformed("a hexadecimal field has an odd length"));
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for index in (0..bytes.len()).step_by(2) {
        let high = hex_value(bytes[index]).ok_or(malformed("a field is not hexadecimal"))?;
        let low = hex_value(bytes[index + 1]).ok_or(malformed("a field is not hexadecimal"))?;
        out.push((high << 4) | low);
    }
    Ok(out)
}

/// The value of one hexadecimal digit.
const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// An integer field of a JSON object.
fn integer(value: &JsonValue) -> Option<u64> {
    let number = *value.get::<f64>()?;
    if !number.is_finite() || number < 0.0 {
        return None;
    }
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "finite and non-negative; the comparison below rejects anything a u64 cannot hold"
    )]
    let truncated = number as u64;
    #[expect(
        clippy::cast_precision_loss,
        reason = "comparing back against the original is the point of the check"
    )]
    let exact = truncated as f64;
    (exact == number).then_some(truncated)
}

/// A malformed field, in one phrase.
const fn malformed(reason: &'static str) -> Error {
    Error::ImportMalformed { reason }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The scrypt parameters the format uses, with a salt short enough for a test to run fast.
    fn parameters(cost: u64) -> scrypt::Params {
        #[expect(
            clippy::cast_possible_truncation,
            reason = "the test passes a small cost"
        )]
        let log_n = cost.trailing_zeros() as u8;
        scrypt::Params::new(log_n, 1, 1).expect("valid parameters")
    }

    #[test]
    fn base64_round_trips_and_refuses_what_it_should() {
        assert_eq!(decode_base64("").expect("empty is valid"), Vec::<u8>::new());
        assert_eq!(decode_base64("QQ==").expect("valid"), b"A");
        assert_eq!(decode_base64("QUI=").expect("valid"), b"AB");
        assert_eq!(decode_base64("QUJD").expect("valid"), b"ABC");
        assert_eq!(
            decode_base64("+/8=").expect("valid"),
            vec![0xFB, 0xFF],
            "the standard alphabet, not the URL-safe one"
        );

        for bad in ["Q", "QQ=", "QQ===", "Q!==", "QQ==QQ=="] {
            assert!(
                decode_base64(bad).is_err(),
                "{bad} is not valid base64 and must be refused"
            );
        }
    }

    #[test]
    fn hex_refuses_odd_lengths_and_foreign_characters() {
        assert_eq!(
            decode_hex("deadBEEF").expect("valid"),
            vec![0xDE, 0xAD, 0xBE, 0xEF]
        );
        assert!(decode_hex("abc").is_err());
        assert!(decode_hex("zz").is_err());
    }

    #[test]
    fn cost_parameters_are_bounded_before_the_derivation_runs() {
        assert!(
            kdf_parameters(32_768, 8, 1).is_ok(),
            "what a real export uses"
        );

        for (cost, block, parallel, expected) in [
            (30_000, 8, 1, "power of two"),
            (1 << 40, 8, 1, "higher than this reader accepts"),
            (32_768, 0, 1, "block size is out of range"),
            (32_768, 4096, 1, "block size is out of range"),
            (32_768, 8, 0, "parallelisation parameter is out of range"),
            (32_768, 8, 64, "parallelisation parameter is out of range"),
            (1 << 20, 32, 1, "more memory than this reader allows"),
        ] {
            match kdf_parameters(cost, block, parallel) {
                Err(Error::ImportInvalidKdfParameters { reason }) => assert!(
                    reason.contains(expected),
                    "cost={cost} block={block} parallel={parallel}: {reason} should mention {expected}"
                ),
                other => panic!(
                    "cost={cost} block={block} parallel={parallel} must be refused, actual {other:?}"
                ),
            }
        }
    }

    #[test]
    fn the_derivation_produces_the_parameters_the_file_asked_for() {
        let params = kdf_parameters(16_384, 8, 1).expect("valid");
        assert_eq!(u32::from(params.log_n()), 14);
        assert_eq!(params.r(), 8);
        assert_eq!(params.p(), 1);

        // Two derivations of the same input agree, and a different password does not: the only
        // property the reader needs from the derivation itself.
        let salt = [7_u8; 32];
        let mut first = [0_u8; KEY_LEN];
        let mut second = [0_u8; KEY_LEN];
        let mut other = [0_u8; KEY_LEN];
        let params = parameters(16);
        scrypt::scrypt(b"password", &salt, &params, &mut first).expect("derives");
        scrypt::scrypt(b"password", &salt, &params, &mut second).expect("derives");
        scrypt::scrypt(b"passwore", &salt, &params, &mut other).expect("derives");
        assert_eq!(first, second);
        assert_ne!(first, other);
    }

    /// The cost parameter the tests use: 2^14 with a block size of 8 is 16 MiB, which keeps a
    /// test fast while still going through the whole derivation.
    const TEST_COST: u64 = 1 << 14;

    /// Hexadecimal text, which the format writes for salts, keys, nonces and tags.
    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    /// Standard base64 with padding, which the format writes for the database.
    fn to_base64(bytes: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
        for chunk in bytes.chunks(3) {
            let mut block = [0_u8; 3];
            block[..chunk.len()].copy_from_slice(chunk);
            let bits =
                (u32::from(block[0]) << 16) | (u32::from(block[1]) << 8) | u32::from(block[2]);
            let letters = [
                ALPHABET[((bits >> 18) & 0x3F) as usize],
                ALPHABET[((bits >> 12) & 0x3F) as usize],
                ALPHABET[((bits >> 6) & 0x3F) as usize],
                ALPHABET[(bits & 0x3F) as usize],
            ];
            let keep = chunk.len() + 1;
            for (index, letter) in letters.iter().enumerate() {
                out.push(if index < keep { *letter as char } else { '=' });
            }
        }
        out
    }

    /// Encrypts with AES-256-GCM and returns the ciphertext and the parameters beside it, in the
    /// shape the format stores them.
    fn seal(
        key: &[u8; KEY_LEN],
        plaintext: &[u8],
        nonce_byte: u8,
    ) -> (Vec<u8>, [u8; NONCE_LEN], [u8; TAG_LEN]) {
        let nonce = [nonce_byte; NONCE_LEN];
        let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(*key));
        let mut buffer = plaintext.to_vec();
        cipher
            .encrypt_in_place(&Nonce::from(nonce), &[], &mut buffer)
            .expect("encryption cannot fail");
        let tag: [u8; TAG_LEN] = buffer
            .split_off(buffer.len() - TAG_LEN)
            .try_into()
            .expect("the tag has the right length");
        (buffer, nonce, tag)
    }

    /// Builds an encrypted export holding `database`, as the exporter would write it.
    fn encrypted_export(password: &[u8], master: &[u8; KEY_LEN], database: &str) -> String {
        let salt = [0x11_u8; 32];
        let mut derived = [0_u8; KEY_LEN];
        scrypt::scrypt(password, &salt, &parameters(TEST_COST), &mut derived).expect("derives");

        let (slot_key, slot_nonce, slot_tag) = seal(&derived, master, 0x22);
        let (db_ciphertext, db_nonce, db_tag) = seal(master, database.as_bytes(), 0x33);

        format!(
            r#"{{"version":1,
                 "header":{{"slots":[{{"type":1,"n":{TEST_COST},"r":1,"p":1,
                     "salt":"{}","key":"{}",
                     "key_params":{{"nonce":"{}","tag":"{}"}}}}],
                   "params":{{"nonce":"{}","tag":"{}"}}}},
                 "db":"{}"}}"#,
            to_hex(&salt),
            to_hex(&slot_key),
            to_hex(&slot_nonce),
            to_hex(&slot_tag),
            to_hex(&db_nonce),
            to_hex(&db_tag),
            to_base64(&db_ciphertext),
        )
    }

    /// A database holding one entry, as the plaintext reader expects to find it.
    const DATABASE: &str = r#"{"version":3,"entries":[
        {"type":"totp","uuid":"11111111-1111-1111-1111-111111111111","name":"GitHub",
         "issuer":"GitHub","note":"","info":{"secret":"JBSWY3DPEHPK3PXP","algo":"SHA1","digits":6,"period":30}}],
        "groups":[]}"#;

    #[test]
    fn the_password_opens_an_encrypted_export() {
        let text = encrypted_export(b"test", &[9_u8; KEY_LEN], DATABASE);
        let report = crate::import::import(
            text.as_bytes(),
            crate::import::ImportFormat::Json,
            1_700_000_000,
            Some(b"test"),
        )
        .expect("the export opens");

        assert!(report.problems.is_empty(), "actual {:?}", report.problems);
        assert_eq!(report.entries.len(), 1);
        assert_eq!(report.entries[0].entry.name, "GitHub");
        assert_eq!(
            report.entries[0].entry.kind,
            crate::vault::EntryKind::Totp { period: 30 }
        );
    }

    #[test]
    fn base64_encoding_round_trips_through_the_decoder() {
        for length in 0..12_usize {
            let bytes: Vec<u8> = (0..length)
                .map(|index| (index as u8).wrapping_mul(37))
                .collect();
            let encoded = to_base64(&bytes);
            assert_eq!(
                decode_base64(&encoded).expect("valid"),
                bytes,
                "length {length} encodes to {encoded}"
            );
        }
    }

    #[test]
    fn a_wrong_password_and_a_modified_slot_report_the_same_thing() {
        let good = encrypted_export(b"test", &[9_u8; KEY_LEN], DATABASE);
        let wrong = crate::import::import(
            good.as_bytes(),
            crate::import::ImportFormat::Json,
            0,
            Some(b"wrong password"),
        );
        assert!(
            matches!(wrong, Err(Error::ImportWrongPassword)),
            "a wrong password: actual {wrong:?}"
        );

        // The same export with one hexadecimal digit of the encrypted key changed: the reader
        // cannot tell this apart from a wrong password, and must not pretend to.
        let key_start = good.find("\"key\":\"").expect("the key is there") + 7;
        let mut bytes = good.clone().into_bytes();
        bytes[key_start] = if bytes[key_start] == b'0' { b'1' } else { b'0' };
        let modified = String::from_utf8(bytes).expect("still text");
        let tampered = crate::import::import(
            modified.as_bytes(),
            crate::import::ImportFormat::Json,
            0,
            Some(b"test"),
        );
        assert!(
            matches!(tampered, Err(Error::ImportWrongPassword)),
            "a modified slot: actual {tampered:?}"
        );
    }

    #[test]
    fn a_database_that_does_not_open_is_corrupted_rather_than_a_wrong_password() {
        let good = encrypted_export(b"test", &[9_u8; KEY_LEN], DATABASE);
        // Break the database only: the slot still authenticates, so the password was accepted.
        let database_start = good.find("\"db\":\"").expect("the database is there") + 6;
        let mut bytes = good.into_bytes();
        bytes[database_start] = if bytes[database_start] == b'A' {
            b'B'
        } else {
            b'A'
        };
        let broken = String::from_utf8(bytes).expect("still text");

        let result = crate::import::import(
            broken.as_bytes(),
            crate::import::ImportFormat::Json,
            0,
            Some(b"test"),
        );
        assert!(
            matches!(result, Err(Error::ImportCorrupted)),
            "actual {result:?}"
        );
    }

    #[test]
    fn an_export_with_no_password_slot_says_so() {
        let text = r#"{"version":1,"header":{"slots":[{"type":2,"key":"00","key_params":{"nonce":"00","tag":"00"}}],"params":{"nonce":"00","tag":"00"}},"db":"AAAA"}"#;
        let result = crate::import::import(
            text.as_bytes(),
            crate::import::ImportFormat::Json,
            0,
            Some(b"test"),
        );
        assert!(
            matches!(result, Err(Error::ImportEncryptionUnsupported { .. })),
            "actual {result:?}"
        );
    }

    #[test]
    fn an_absurd_cost_parameter_is_refused_without_deriving_anything() {
        // 2^24 with a block size of 8 asks for 16 GiB. The refusal has to happen before the
        // derivation, which would already have allocated.
        let text = encrypted_export(b"test", &[9_u8; KEY_LEN], DATABASE)
            .replace(&format!("\"n\":{TEST_COST}"), "\"n\":16777216");
        let started = std::time::Instant::now();
        let result = crate::import::import(
            text.as_bytes(),
            crate::import::ImportFormat::Json,
            0,
            Some(b"test"),
        );
        assert!(
            matches!(result, Err(Error::ImportInvalidKdfParameters { .. })),
            "actual {result:?}"
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "the refusal must not have run the derivation"
        );
    }

    #[test]
    fn a_slot_without_the_expected_fields_is_malformed_rather_than_wrong() {
        let slot = std::collections::HashMap::new();
        match open_slot(&slot, b"password") {
            Err(Error::ImportMalformed { reason }) => assert!(reason.contains("cost parameter")),
            other => panic!("actual {other:?}"),
        }
    }
}
