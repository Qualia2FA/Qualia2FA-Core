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

//! Fuzz target: vault file parsing.
//!
//! # Input surface
//!
//! A vault file is input an **attacker can construct in full**: it travels through a
//! cloud drive of the user's choosing, a QR code or another device, and none of
//! those channels is under this application's control. The parser handles a byte
//! stream entirely decided by the adversary, in which every length field may hold
//! any value.
//!
//! # Properties covered
//!
//! 1. **Out-of-bounds and panics** — inputs such as "claims 4 GiB of ciphertext",
//!    "nothing after the length prefix" or "the length field is missing after the
//!    tag" must not crash the process. This is the denial-of-service defense: an
//!    authenticator that a malicious file can crash is unusable.
//! 2. **Unbounded allocation** — a length field must be compared against the limit
//!    before it is used for an allocation. Otherwise a 100-byte file makes the
//!    application request 4 GiB of memory.
//!
//! # AEAD stops most inputs before parsing, so it has to be bypassed on purpose
//!
//! Every record of this file is protected by XChaCha20-Poly1305, so a casually
//! constructed byte stream is almost certain to be rejected at the authentication
//! step and never reaches the entry-plaintext parsing logic (the place most easily
//! written wrong). To make fuzz really cover it, this target builds a **valid
//! skeleton file encrypted with a known key**, with the fuzz input landing inside or
//! around the ciphertext:
//!
//! - Mode 1: parse the whole input as a file. Covers the file header and the record
//!   framing.
//! - Mode 2: insert the input as the **record ciphertext** into a valid skeleton.
//!   The input then enters the parsing loop of `decode_entry`, after passing (or
//!   failing) authentication.
//! - Mode 3: parse the input as a portable `.q2fa` container, and parse it again
//!   wrapped in a valid plain-container header. There the two length fields come
//!   from the file, and the arithmetic around them is the part a crafted small file
//!   can get wrong.
//!
//! Mode 2 is the main reason the target exists — "skip unknown nodes" in
//! `decode_entry` is the whole implementation of forward compatibility, and the
//! place most easily written with an out-of-bounds error.
//!
//! # Key point: the skeleton must use a key that can be reconstructed
//!
//! `MasterKey::generate()` differs every time; encrypting with it would leave the
//! fuzz target unable to open the file it built itself, wasting mode 2. An
//! input-derived key of fixed length is used instead, so that "encrypt" and "parse"
//! use the same key.
//!
//! Preconditions: no feature flags. Mode 2 builds a valid skeleton with a known key
//! on purpose, in order to reach the plaintext parsing behind AEAD.

#![no_main]

use libfuzzer_sys::fuzz_target;
use qualia2fa_core::otp;
use qualia2fa_core::vault::{self, Entry, EntryId, MasterKey, VaultFile};

/// Derives a deterministic 32-byte key from the input.
///
/// Takes the first 32 bytes and zero-pads a short input. **This is not a key
/// derivation function** — it only lets the fuzz target open the file it built
/// itself, and it takes part in no real security decision.
fn master_from(data: &[u8]) -> MasterKey {
    let mut key = [0_u8; vault::MASTER_KEY_LEN];
    let take = data.len().min(vault::MASTER_KEY_LEN);
    key[..take].copy_from_slice(&data[..take]);
    MasterKey::from_bytes(key.to_vec().into()).expect("the length is always 32")
}

fuzz_target!(|data: &[u8]| {
    let master = master_from(data);

    // ── Mode 1: parse the whole input as a file ─────────────────────────────
    check_file(clone_key(&master), data);

    // ── Mode 2: the input as the record ciphertext of a valid skeleton ──────
    check_embedded_record(&master, data);

    // ── Mode 3: the input as a portable container, and inside one ───────────
    check_portable(data);
    check_wrapped_portable(data);
});

/// Parses the input as a portable `.q2fa` container.
///
/// Every length in that container is read from the file, so this covers "the declared payload
/// does not match the file", "the declared payload is larger than the limit" and "the header is
/// shorter than it claims" — none of which may panic or allocate what the header asks for.
fn check_portable(data: &[u8]) {
    if let Ok(parsed) = qualia2fa_core::portable::parse(data) {
        let _ = parsed.kind();
        let _ = parsed.vault();
    }
}

/// Wraps the input in a well-formed plain container header and parses that.
///
/// The header is valid by construction, so the fuzz input reaches the length arithmetic instead
/// of being rejected at the magic; a random input never gets that far on its own.
fn check_wrapped_portable(data: &[u8]) {
    let mut file = Vec::with_capacity(
        qualia2fa_core::portable::PLAIN_HEADER_LEN + data.len(),
    );
    file.extend_from_slice(qualia2fa_core::portable::PLAIN_MAGIC);
    file.push(qualia2fa_core::portable::VERSION);
    file.push(0);
    file.extend_from_slice(&[0x11_u8; vault::MASTER_KEY_LEN]);
    let len = u32::try_from(data.len()).unwrap_or(u32::MAX);
    file.extend_from_slice(&len.to_be_bytes());
    file.extend_from_slice(data);

    if let Ok(parsed) = qualia2fa_core::portable::parse(&file) {
        let _ = parsed.vault();
    }
}

/// Parses a byte string and, on success, verifies the round-trip.
fn check_file(master: MasterKey, data: &[u8]) {
    let Ok(file) = VaultFile::parse(master, data) else {
        return;
    };

    let Ok(again) = file.serialize() else {
        return;
    };

    let master2 = master_key_of(&file);
    let Ok(reparsed) = VaultFile::parse(master2, &again) else {
        panic!("a file this target serialized itself cannot be parsed back");
    };
    assert_eq!(
        reparsed.vault().len(),
        file.vault().len(),
        "the entry count changed after the round trip"
    );
    assert_eq!(
        reparsed.vault().tombstone_count(),
        file.vault().tombstone_count(),
        "the tombstone count changed after the round trip"
    );
}

/// Takes out the copy of the master key held by the file (used to parse it again).
fn master_key_of(file: &VaultFile) -> MasterKey {
    let bytes = vault::master_key_to_bytes(file.master_key());
    MasterKey::from_bytes(bytes).expect("the length is correct")
}

/// Inserts the input as the record ciphertext into a skeleton file and parses that.
///
/// The skeleton is encrypted from a known entry, so its **non-ciphertext parts are
/// all valid**: magic, version, record kind, `entry_id`, nonce and length are
/// correct. The input bytes are placed in the ciphertext position, so the
/// exploration power of fuzz concentrates on the path "how is the plaintext parsed
/// once the ciphertext is decrypted".
///
/// The skeleton layout is fixed: a 14-byte file header, a 1-byte kind, a 16-byte
/// `entry_id`, a 24-byte nonce and a 4-byte length, followed by the ciphertext,
/// which is replaced as a whole by the fuzz input. The length field is rewritten to
/// the actual length of the input, otherwise the parser stops at the length check
/// and never reaches the logic after ciphertext decryption.
fn check_embedded_record(master: &MasterKey, data: &[u8]) {
    let mut file = VaultFile::with_master_key(clone_key(master));
    let Ok(_) = file.vault_mut().insert(sample_entry()) else {
        return;
    };
    let Ok(skeleton) = file.serialize() else {
        return;
    };

    const CIPHERTEXT_OFFSET: usize = 14 + 1 + EntryId::LEN + vault::NONCE_LEN + 4;
    if skeleton.len() < CIPHERTEXT_OFFSET {
        return;
    }

    let mut mutated = skeleton[..CIPHERTEXT_OFFSET].to_vec();
    mutated.extend_from_slice(data);
    let len = u32::try_from(data.len()).unwrap_or(u32::MAX);
    mutated[CIPHERTEXT_OFFSET - 4..CIPHERTEXT_OFFSET].copy_from_slice(&len.to_be_bytes());

    check_file(clone_key(master), &mutated);
}

/// Copies a master key.
///
/// `MasterKey` deliberately does not implement `Clone` (that would make silently
/// copying a secret something anyone can do), so the copy goes explicitly through
/// bytes here — doing it this way in a fuzz target is deliberate: it keeps the fact
/// that a key really is copied visible in the code.
fn clone_key(master: &MasterKey) -> MasterKey {
    MasterKey::from_bytes(vault::master_key_to_bytes(master)).expect("the length is correct")
}

/// A valid entry used to build the skeleton.
fn sample_entry() -> Entry {
    Entry::new(
        "fuzz".into(),
        Some("Qualia2FA".into()),
        "alice".into(),
        otp::OtpSecret::from_base32("JBSWY3DPEHPK3PXP").expect("valid Base32"),
        otp::Algorithm::Sha1,
        otp::Digits::SIX,
        vault::EntryKind::Totp { period: 30 },
        String::new(),
        0,
        0,
    )
    .expect("all fields are valid")
}
