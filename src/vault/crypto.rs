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

//! Cryptographic primitives of the vault: master key, subkey derivation, record AEAD.
//!
//! # Scope
//!
//! Turning one byte string into another and owning the lifetime of key material. The
//! file format, entry semantics and atomic writes live in other modules.
//!
//! # Three invariants
//!
//! 1. **The random nonce is 192-bit.** Devices encrypt independently and without
//!    central coordination, so a random nonce is the only workable choice; 96 bits
//!    reaches the birthday bound at vault scale. See [`Nonce::LEN`].
//! 2. **The AAD binds entry identity and format version.** Without it, the ciphertext
//!    of entry A could be moved to the position of entry B, or the ciphertext of an
//!    older format could be placed into a newer file: both moves would pass the AEAD,
//!    because the ciphertext itself is valid. See [`build_aad`].
//! 3. **The master key is only used through HKDF-derived subkeys**, never directly as
//!    an AEAD key. See [`entry_key`].

use super::entry::EntryId;
use crate::{Error, ExposeSecret, Result, SecretBytes};
use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::Sha256;
use subtle::ConstantTimeEq as _;

/// Length of the master key in bytes.
///
/// 256-bit. Symmetric key lengths above 256-bit give no practical security gain
/// (128-bit effective strength under Grover's algorithm is the limit of quantum
/// search), while they make a recovery key longer and harder to copy by hand.
pub const MASTER_KEY_LEN: usize = 32;

/// The master key: a 256-bit CSPRNG random value.
///
/// # It is the only long-lived secret of the application
///
/// OTP seeds, device identities and sync payloads are all derived from it or encrypted
/// under it. With no central server and no account, there is no recovery path: a lost
/// key is lost. The key is meant to be held by the platform hardware key store (Windows
/// TPM).
///
/// # Boundaries of secret protection
///
/// - No `Clone` (which would silently copy the plaintext) and no plaintext in `Debug`
///   output.
/// - Erased on `Drop` (guaranteed by [`SecretBytes`]).
/// - The plaintext is **not** protected from being copied into registers, stack copies
///   or the swap file; `forbid(unsafe_code)` rules out `mlock` to prevent paging.
/// - Malicious code in the same process is **not** defended against. Reading the
///   plaintext requires an explicit call to [`MasterKey::expose`], which keeps every
///   use site visible in code review.
pub struct MasterKey(SecretBytes);

impl MasterKey {
    /// Generates a new random master key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::RandomnessUnavailable`] when the OS random source is
    /// unavailable, and there is no fallback to a user-space PRNG: a predictable master
    /// key would let an attacker decrypt every entry, and such a failure would be
    /// silent. The key bytes are handed to [`SecretBytes`], which owns the buffer and
    /// erases it on drop.
    pub fn generate() -> Result<Self> {
        let mut bytes = [0_u8; MASTER_KEY_LEN];
        crate::getrandom::fill(&mut bytes).map_err(|_| Error::RandomnessUnavailable)?;
        Ok(Self(Vec::from(bytes).into()))
    }

    /// Restores the master key from existing bytes.
    ///
    /// **Security contract**: the caller must ensure that `bytes` come from a trusted
    /// source and are erased afterwards. Device login is the only consumer: the master
    /// key is recovered from the platform key store or from an out-of-band channel (a
    /// QR code). This is **not** a way to keep a master key in an ordinary file.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MasterKeyWrongLength`] when the length is not
    /// [`MASTER_KEY_LEN`]. A wrong length is rejected rather than padded or truncated:
    /// padding would silently weaken the key, and truncation would make two devices
    /// derive different subkeys.
    pub fn from_bytes(bytes: SecretBytes) -> Result<Self> {
        if bytes.expose_secret().len() != MASTER_KEY_LEN {
            return Err(Error::MasterKeyWrongLength {
                expected: MASTER_KEY_LEN,
                actual: bytes.expose_secret().len(),
            });
        }
        Ok(Self(bytes))
    }

    /// Explicitly reads the master key plaintext.
    ///
    /// `Deref` and `AsRef` are deliberately not implemented: they would read the
    /// plaintext silently in many places, whereas an explicit method name keeps every
    /// use site visible to `grep` and code review.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        self.0.expose_secret()
    }

    /// Constant-time equality.
    ///
    /// Used where two independently recovered keys are compared — for example "the password
    /// wrap and the platform wrap must yield the same master key". A short-circuiting `==`
    /// would leak how many leading bytes matched.
    #[must_use]
    pub fn matches(&self, other: &Self) -> bool {
        let left = self.expose();
        let right = other.expose();
        if left.len() != right.len() {
            return false;
        }
        let mut difference = 0_u8;
        for (a, b) in left.iter().zip(right.iter()) {
            difference |= a ^ b;
        }
        difference == 0
    }
}

impl core::fmt::Debug for MasterKey {
    /// Prints the type name only, not even the length.
    ///
    /// The length carries no diagnostic value here, since it is a constant.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("MasterKey([REDACTED])")
    }
}

/// Serialized form of the master key.
///
/// For the device login flow only: it hands the master key to the platform key store or
/// to a QR-code envelope. The returned container is erased on `Drop`, but the caller
/// should still hand it over as soon as possible.
///
/// The [`SecretBytes`] clone is intentional: the caller takes independent ownership of
/// one copy, and both copies erase themselves.
#[must_use]
pub fn master_key_to_bytes(key: &MasterKey) -> SecretBytes {
    key.0.clone()
}

/// Length of a nonce in bytes.
///
/// **192-bit, not a tunable parameter.** Devices encrypt independently and without
/// central coordination, so a random nonce is the only workable choice, and a 96-bit
/// random nonce reaches the birthday bound at vault scale: random-nonce `aes-gcm` is
/// known to be unsafe there.
pub const NONCE_LEN: usize = 24;

/// Length of the Poly1305 authentication tag in bytes.
pub const TAG_LEN: usize = 16;

/// The encryption nonce of a record.
///
/// A **fresh** one is generated for every encryption; nonces are neither reused nor
/// incremented. An incrementing counter would need coordination between devices, and
/// this application has no coordination point.
pub type Nonce = [u8; NONCE_LEN];

/// Generates a new random nonce from the OS random source.
pub(crate) fn random_nonce() -> Result<Nonce> {
    let mut nonce = [0_u8; NONCE_LEN];
    crate::getrandom::fill(&mut nonce).map_err(|_| Error::RandomnessUnavailable)?;
    Ok(nonce)
}

/// HKDF context string for subkey derivation.
///
/// The master key also takes part in device pairing and recovery, so keys are derived
/// per purpose: a subkey leaked in one context exposes neither the master key itself nor
/// the data of another context.
///
/// The string carries a version (`v1`): a future algorithm or key-length change uses a
/// new string while old data stays readable under the old one.
const HKDF_INFO_ENTRY: &[u8] = b"Qualia2FA vault v1 entry encryption";

/// HKDF salt.
///
/// Fixed and all-zero. HKDF's salt separates several unrelated protocols that share one
/// input key material; here the input material (the master key) is already 256-bit
/// uniformly random and dedicated to this application, so no such sharing exists. A
/// fixed salt also keeps derivation **deterministic**: the same master key yields the
/// same subkey on every device, otherwise synced entries could not be opened.
///
/// Domain separation is carried by [`HKDF_INFO_ENTRY`], which is the right tool for it.
const HKDF_SALT: [u8; 32] = [0_u8; 32];

/// Derives the subkey used for entry encryption from the master key.
///
/// Derivation happens on every call and is not cached: HKDF costs two HMAC-SHA256
/// operations, which is negligible for a code generated once every 30 seconds, whereas
/// caching would keep the subkey in memory longer.
///
/// `pub(crate)` rather than private: the sync layer **verifies** that its own key
/// differs from this one, and that check can only use the value produced here.
pub(crate) fn entry_key(master: &MasterKey) -> Result<[u8; 32]> {
    derive_key(master, HKDF_INFO_ENTRY)
}

/// Derives a 32-byte subkey from the master key with a context string.
///
/// # Domain separation relies on `info`
///
/// Every subkey derived from the same master key **must** use a different `info`.
/// Sharing one string between two places is not a slight weakening but full domain
/// confusion: a ciphertext that is valid in one domain is valid in the other, so moving
/// a ciphertext from a sync payload into a vault file would authenticate.
///
/// Extracted into one function so that [`crate::sync`] derives its keys through the same
/// rules instead of repeating the HKDF call.
pub(crate) fn derive_key(master: &MasterKey, info: &[u8]) -> Result<[u8; 32]> {
    derive_key_with_salt(master, &HKDF_SALT, info)
}

/// Derives a 32-byte subkey from the master key with the given salt and context string.
///
/// # The salt is a parameter
///
/// Records of [`crate::sync`] and records of a vault file can carry byte-identical AAD
/// (one kind byte, a 16-byte identifier and a version byte). Identical AAD means the
/// ciphertexts of the two domains are interchangeable: a sync payload fed to the vault
/// parser as a file would authenticate.
///
/// Distinct salts separate the domains **structurally**: their subkeys diverge during
/// HKDF-Extract, independently of how the AAD is laid out.
///
/// # Errors
///
/// Fails only when the output length exceeds 255 × HashLen, which 32 bytes cannot
/// reach; the `Result` exists to honour the crate's no-panic rule.
pub(crate) fn derive_key_with_salt(
    master: &MasterKey,
    salt: &[u8],
    info: &[u8],
) -> Result<[u8; 32]> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), master.expose());
    let mut key = [0_u8; 32];
    hkdf.expand(info, &mut key)
        .map_err(|_| Error::VaultDecryptionFailed)?;
    Ok(key)
}

/// HKDF context string for inner sync records.
///
/// Not a different string from [`HKDF_INFO_ENTRY`]: **the two deliberately share one**,
/// because domain separation is carried by the salt (see [`derive_key_with_salt`]).
/// `info` describes the purpose of a record, and "entry encryption" is the same purpose
/// in both domains.
pub(crate) const HKDF_INFO_SYNC_RECORD: &[u8] = HKDF_INFO_ENTRY;

/// HKDF context string for the outer envelope.
pub(crate) const HKDF_INFO_SYNC_ENVELOPE: &[u8] = b"Qualia2FA sync v1 envelope";

/// Encrypts bytes that are **outside the record format** (the envelope of a sync
/// payload) with an already derived key.
///
/// Unlike [`seal_with_key`], which binds kind + entry ID + version into the AAD, this
/// binds the caller-supplied AAD as is: the envelope's AAD is the whole plaintext
/// header, not the record triple.
///
/// # Errors
///
/// Can only fail when the random source is unavailable.
pub(crate) fn seal_bytes(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Result<(Nonce, Vec<u8>)> {
    let cipher = XChaCha20Poly1305::new(&Key::from(*key));
    let nonce = random_nonce()?;
    let mut buffer = plaintext.to_vec();
    cipher
        .encrypt_in_place(&XNonce::from(nonce), aad, &mut buffer)
        .map_err(|_| Error::VaultDecryptionFailed)?;
    Ok((nonce, buffer))
}

/// Inverse of [`seal_bytes`].
///
/// # Errors
///
/// Any authentication failure returns [`Error::VaultDecryptionFailed`] without
/// distinguishing causes. That is **not** the error the sync layer exposes to callers:
/// [`crate::sync::Payload::open`] translates it into
/// [`Error::SyncAuthenticationFailed`], because an unopenable file and an untrusted sync
/// are handled differently at the application boundary.
pub(crate) fn open_bytes(
    key: &[u8; 32],
    aad: &[u8],
    nonce: &Nonce,
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(&Key::from(*key));
    let mut buffer = ciphertext.to_vec();
    cipher
        .decrypt_in_place(&XNonce::from(*nonce), aad, &mut buffer)
        .map_err(|_| Error::VaultDecryptionFailed)?;
    Ok(buffer)
}

/// Length of the master key check value in bytes.
pub const KEY_CHECK_LEN: usize = 32;

/// HKDF context string for deriving the master key check value.
///
/// Different from [`HKDF_INFO_ENTRY`]: this string is what separates the two domains.
/// Sharing it would make the check value equal to the entry subkey, and the check value
/// is **written into the file in plaintext**.
const HKDF_INFO_KEY_CHECK: &[u8] = b"Qualia2FA vault v1 master key check";

/// Derives the check value that states which master key wrote a file.
///
/// # What it establishes
///
/// The master key takes part only in each record's AEAD, and the file header holds
/// nothing about it, so **an empty vault file parses successfully under any 32-byte
/// key**; a wrong master key would only surface once the user adds a first entry or a
/// first record is synced in. With the check value in the file, `parse` decides whether
/// the key is correct **before reading the first record**.
///
/// # Properties
///
/// The derivation is fixed, so the same master key yields the same check value in every
/// file, and this layer reveals nothing beyond the single bit "the guessed master key is
/// correct". An attacker holding the file could test keys record by record anyway, since
/// the AEAD tag is a ready-made verifier.
///
/// The artefact that resists offline brute force is the **recovery-key file**: its key is
/// encrypted under a key derived from a user passphrase with Argon2id, so every attempt
/// costs 64 MiB of memory and 3 iterations. A vault file holds no passphrase and relies
/// on the master key being 256-bit uniformly random and unenumerable.
///
/// The 32-byte `expand` cannot fail (the HKDF output limit is 255 × 32 bytes), so the
/// `expect` is unreachable. It is used instead of `unwrap` because the crate's no-panic
/// rule admits no exception, and the function returns an array with no error channel.
#[must_use]
pub fn key_check(master: &MasterKey) -> [u8; KEY_CHECK_LEN] {
    let hkdf = Hkdf::<Sha256>::new(Some(&HKDF_SALT), master.expose());
    let mut check = [0_u8; KEY_CHECK_LEN];
    hkdf.expand(HKDF_INFO_KEY_CHECK, &mut check)
        .expect("a 32-byte HKDF output cannot fail");
    check
}

/// Verifies the master key check value stored in a file.
///
/// # Errors
///
/// A wrong length returns [`Error::VaultBadKeyCheck`] (structural); a correct length with
/// a mismatching value returns [`Error::VaultDecryptionFailed`] (authentication). The two
/// are kept apart because the first says the file is malformed while the second says the
/// **master key is wrong or the file was modified**, and the two are handled differently
/// at the application boundary.
///
/// # Constant-time comparison
///
/// The check value is plaintext, so an attacker can call this function repeatedly
/// locally to measure timing. Comparing in constant time costs the same, so there is no
/// reason for a non-constant-time branch here.
pub fn verify_key_check(master: &MasterKey, stored: &[u8]) -> Result<()> {
    let stored: &[u8; KEY_CHECK_LEN] = stored.try_into().map_err(|_| Error::VaultBadKeyCheck)?;
    if key_check(master).ct_eq(stored).into() {
        Ok(())
    } else {
        Err(Error::VaultDecryptionFailed)
    }
}

/// The kind of a record, part of the AAD construction.
///
/// The kind is part of the AAD, so a tombstone's ciphertext cannot be moved into the position of a
/// live entry (or the other way round): a live entry and a tombstone use the same key and the same
/// AEAD, and both are valid ciphertexts that the AEAD alone cannot tell apart.
///
/// # The sync kinds are here but outside the vault file's value range
///
/// The variants cover **two** record sets: `Entry`/`Tombstone` for vault files and
/// `SyncEntry`/`SyncTombstone` for sync payloads. They share one subkey and are
/// separated by the kind byte and by the format version.
///
/// The values sit in the high half (from `0x80`), far from the values that occur in a
/// file (`0x01`/`0x02`), so kinds added to the file format are taken from the low half
/// and cannot collide with the sync kinds. Moreover, [`RecordKind::from_byte`] does
/// **not** accept the sync kinds, so the vault parser reports a sync record inside a file
/// as [`crate::Error::VaultUnknownRecordKind`] instead of accepting it as a valid
/// record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecordKind {
    /// A live entry (vault file).
    Entry,
    /// A tombstone (vault file).
    Tombstone,
    /// A group with its ordering (vault file).
    ///
    /// Added in format version 3. Its identifier occupies the same 16-byte field as an entry
    /// identifier and takes part in the AAD through this kind byte, so a group record can never
    /// be read as an entry.
    Group,
    /// A live entry, found in a **sync payload**.
    SyncEntry,
    /// A tombstone, found in a **sync payload**.
    SyncTombstone,
    /// A group with its ordering, found in a **sync payload**.
    SyncGroup,
}

impl RecordKind {
    /// The byte value written to the file and fed into the AAD.
    ///
    /// **This value is a public contract**: it is part of the AAD, so changing it makes
    /// every existing ciphertext undecryptable.
    pub(crate) const fn as_byte(self) -> u8 {
        match self {
            Self::Entry => 0x01,
            Self::Tombstone => 0x02,
            Self::Group => 0x03,
            Self::SyncEntry => 0x81,
            Self::SyncTombstone => 0x82,
            Self::SyncGroup => 0x83,
        }
    }

    /// Restores a kind from a byte read from a **vault file**.
    ///
    /// Unknown values are rejected (`None`) rather than treated as a live entry: taking
    /// an unknown kind for "probably an entry" would revive a tombstone written by a
    /// future version as a live entry.
    ///
    /// The sync kinds are deliberately absent: they only occur in sync payloads, and the
    /// parser of that layer tries decryption per kind (see the module documentation of
    /// [`crate::sync::record`]).
    pub(crate) const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(Self::Entry),
            0x02 => Some(Self::Tombstone),
            0x03 => Some(Self::Group),
            _ => None,
        }
    }

    /// Restores a kind from a byte read from a **sync payload**.
    ///
    /// # No production call site, but load-bearing
    ///
    /// The payload parser does not choose kinds with this function (it tries decryption
    /// per kind), so the normal path never calls it. It is kept because it defines which
    /// byte values are valid sync record kinds, and the compile-time assertions and unit
    /// tests in `crate::sync` depend on it.
    ///
    /// Strictly disjoint from [`RecordKind::from_byte`]: a device decodes a sync payload
    /// into a set of entries before touching its own vault, so no record kind may be
    /// valid in both layers.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "defined by contract, used by the compile-time assertions and tests of sync; payload parsing tries each kind instead of coming through here"
        )
    )]
    pub(crate) const fn from_sync_byte(byte: u8) -> Option<Self> {
        match byte {
            0x81 => Some(Self::SyncEntry),
            0x82 => Some(Self::SyncTombstone),
            0x83 => Some(Self::SyncGroup),
            _ => None,
        }
    }
}

/// AAD length in bytes: 1 (kind) + 16 (entry_id) + 1 (format version).
const AAD_LEN: usize = 1 + EntryId::LEN + 1;

/// Builds the additional authenticated data (AAD).
///
/// # The three moves it blocks
///
/// 1. **Ciphertext moved between entries** — the ciphertext of entry A copied to the
///    position of entry B. The AAD contains `entry_id`, so authentication fails as soon
///    as the position changes.
/// 2. **Ciphertext moved between kinds** — a tombstone ciphertext used as an entry
///    ciphertext (a deletion silently undone) or the reverse (an entry silently
///    deleted). The AAD contains [`RecordKind`].
/// 3. **Ciphertext moved between format versions** — an old-format ciphertext placed
///    into a new-format file to bypass the new format's extra checks. The AAD contains
///    the format version.
///
/// The layout is a fixed-length byte string rather than a self-describing encoding, so it
/// is easy to check byte by byte, and it evolves together with
/// [`crate::vault::FORMAT_VERSION`].
pub(crate) fn build_aad(
    kind: RecordKind,
    record_id: &[u8; EntryId::LEN],
    format_version: u8,
) -> [u8; AAD_LEN] {
    let mut aad = [0_u8; AAD_LEN];
    aad[0] = kind.as_byte();
    aad[1..1 + EntryId::LEN].copy_from_slice(record_id);
    aad[AAD_LEN - 1] = format_version;
    aad
}

/// Encrypts record plaintext.
///
/// The returned ciphertext **includes** the 16-byte Poly1305 authentication tag
/// (appended at the end), so its length is `plaintext.len() + TAG_LEN`. The caller stores
/// the nonce in the file: a nonce is not a secret, but tampering with it makes decryption
/// fail, which is the wanted outcome.
///
/// # Errors
///
/// Can only fail when the random source is unavailable
/// ([`Error::RandomnessUnavailable`]). Encryption itself cannot fail:
/// XChaCha20-Poly1305 is defined for inputs of any length.
pub(crate) fn seal(
    master: &MasterKey,
    kind: RecordKind,
    record_id: &[u8; EntryId::LEN],
    format_version: u8,
    plaintext: &[u8],
) -> Result<(Nonce, Vec<u8>)> {
    let key = entry_key(master)?;
    seal_with_key(&key, kind, record_id, format_version, plaintext)
}

/// Encrypts with a subkey that is **already derived**.
///
/// Extracted so that one sync derives its subkey once: a payload holds hundreds or
/// thousands of records, and re-deriving HKDF per record would multiply two HMAC-SHA256
/// operations by the record count. The plaintext is encrypted in place, so no second copy
/// of it stays in memory.
///
/// # Errors
///
/// Can only fail when the random source is unavailable
/// ([`Error::RandomnessUnavailable`]).
pub(crate) fn seal_with_key(
    key: &[u8; 32],
    kind: RecordKind,
    record_id: &[u8; EntryId::LEN],
    format_version: u8,
    plaintext: &[u8],
) -> Result<(Nonce, Vec<u8>)> {
    let cipher = XChaCha20Poly1305::new(&Key::from(*key));
    let nonce = random_nonce()?;
    let aad = build_aad(kind, record_id, format_version);
    let mut buffer = plaintext.to_vec();
    cipher
        .encrypt_in_place(&XNonce::from(nonce), &aad, &mut buffer)
        .map_err(|_| Error::VaultDecryptionFailed)?;
    Ok((nonce, buffer))
}

/// Decrypts record ciphertext.
///
/// # Errors
///
/// Any authentication failure returns [`Error::VaultDecryptionFailed`], **without**
/// distinguishing a wrong key, a modified ciphertext and a mismatching AAD. Telling them
/// apart would help an attacker (it reveals whether a guessed key is right and which part
/// was modified) and gives the user nothing actionable: all three mean that this vault
/// cannot be opened.
pub(crate) fn open(
    master: &MasterKey,
    kind: RecordKind,
    record_id: &[u8; EntryId::LEN],
    format_version: u8,
    nonce: &Nonce,
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let key = entry_key(master)?;
    open_with_key(&key, kind, record_id, format_version, nonce, ciphertext)
}

/// Decrypts with a subkey that is **already derived**. Same reasoning as
/// [`seal_with_key`].
///
/// # Errors
///
/// Any authentication failure returns [`Error::VaultDecryptionFailed`], **without**
/// distinguishing a wrong key, a modified ciphertext and a mismatching AAD.
pub(crate) fn open_with_key(
    key: &[u8; 32],
    kind: RecordKind,
    record_id: &[u8; EntryId::LEN],
    format_version: u8,
    nonce: &Nonce,
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(&Key::from(*key));
    let aad = build_aad(kind, record_id, format_version);
    let mut buffer = ciphertext.to_vec();
    cipher
        .decrypt_in_place(&XNonce::from(*nonce), &aad, &mut buffer)
        .map_err(|_| Error::VaultDecryptionFailed)?;
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> MasterKey {
        MasterKey::generate().expect("OS randomness available")
    }

    #[test]
    fn master_key_is_32_bytes_and_debug_is_redacted() {
        let k = key();
        assert_eq!(k.expose().len(), MASTER_KEY_LEN);

        let debug = format!("{k:?}");
        assert!(debug.contains("REDACTED"), "Debug is not redacted: {debug}");
        for byte in k.expose() {
            assert!(
                !debug.contains(&format!("{byte}")),
                "Debug leaked key bytes: {debug}"
            );
        }
    }

    #[test]
    fn master_key_rejects_wrong_length() {
        for len in [0_usize, 1, 31, 33, 64] {
            let bytes: SecretBytes = vec![0_u8; len].into();
            match MasterKey::from_bytes(bytes) {
                Err(Error::MasterKeyWrongLength { expected, actual }) => {
                    assert_eq!(expected, MASTER_KEY_LEN);
                    assert_eq!(actual, len);
                }
                other => panic!("length {len} must be rejected, actual ok={}", other.is_ok()),
            }
        }
    }

    #[test]
    fn master_key_accepts_exactly_32_bytes() {
        let bytes: SecretBytes = vec![7_u8; MASTER_KEY_LEN].into();
        let k = MasterKey::from_bytes(bytes).expect("correct length");
        assert_eq!(k.expose(), &[7_u8; MASTER_KEY_LEN]);
    }

    /// `matches` compares the whole key, and a difference in the last byte is enough.
    #[test]
    fn master_key_matches_compares_all_bytes() {
        let a = MasterKey::from_bytes(vec![5_u8; MASTER_KEY_LEN].into()).expect("correct length");
        let b = MasterKey::from_bytes(vec![5_u8; MASTER_KEY_LEN].into()).expect("correct length");
        assert!(a.matches(&b), "equal keys must match");

        let mut last = [5_u8; MASTER_KEY_LEN];
        last[MASTER_KEY_LEN - 1] = 6;
        let c = MasterKey::from_bytes(Vec::from(last).into()).expect("correct length");
        assert!(
            !a.matches(&c),
            "a difference in the last byte must be detected"
        );

        let mut first = [5_u8; MASTER_KEY_LEN];
        first[0] = 4;
        let d = MasterKey::from_bytes(Vec::from(first).into()).expect("correct length");
        assert!(
            !a.matches(&d),
            "a difference in the first byte must be detected"
        );
    }

    /// The same master key must derive the same subkey, otherwise synced entries cannot
    /// be opened.
    #[test]
    fn derived_key_is_deterministic() {
        let bytes: SecretBytes = vec![3_u8; MASTER_KEY_LEN].into();
        let a = MasterKey::from_bytes(bytes.clone()).expect("correct length");
        let b = MasterKey::from_bytes(bytes).expect("correct length");
        assert_eq!(
            entry_key(&a).expect("derivation succeeds"),
            entry_key(&b).expect("derivation succeeds")
        );
    }

    /// Different master keys must derive different subkeys.
    #[test]
    fn derived_key_differs_per_master_key() {
        let a = MasterKey::from_bytes(vec![1_u8; MASTER_KEY_LEN].into()).expect("correct length");
        let b = MasterKey::from_bytes(vec![2_u8; MASTER_KEY_LEN].into()).expect("correct length");
        assert_ne!(
            entry_key(&a).expect("derivation succeeds"),
            entry_key(&b).expect("derivation succeeds")
        );
    }

    /// A subkey must **not** equal the master key itself.
    ///
    /// Catches a derivation that degenerates into the identity map.
    #[test]
    fn derived_key_is_not_the_master_key() {
        let bytes: SecretBytes = vec![5_u8; MASTER_KEY_LEN].into();
        let k = MasterKey::from_bytes(bytes).expect("correct length");
        assert_ne!(
            entry_key(&k).expect("derivation succeeds"),
            *k.expose().first_chunk::<32>().expect("32 bytes")
        );
    }

    #[test]
    fn seal_then_open_roundtrips() {
        let k = key();
        let id = EntryId::generate().expect("OS randomness available");
        let plaintext = b"the quick brown fox";

        let (nonce, ciphertext) =
            seal(&k, RecordKind::Entry, id.as_bytes(), 1, plaintext).expect("sealing succeeds");
        assert_eq!(ciphertext.len(), plaintext.len() + TAG_LEN);
        assert_ne!(
            &ciphertext[..plaintext.len()],
            &plaintext[..],
            "the ciphertext equals the plaintext"
        );

        let opened = open(&k, RecordKind::Entry, id.as_bytes(), 1, &nonce, &ciphertext)
            .expect("opening succeeds");
        assert_eq!(opened, plaintext);
    }

    /// Every encryption must use a fresh nonce; the security of a random nonce depends
    /// on it.
    #[test]
    fn each_seal_uses_a_fresh_nonce() {
        let k = key();
        let id = EntryId::generate().expect("OS randomness available");
        let (n1, _) =
            seal(&k, RecordKind::Entry, id.as_bytes(), 1, b"same").expect("sealing succeeds");
        let (n2, _) =
            seal(&k, RecordKind::Entry, id.as_bytes(), 1, b"same").expect("sealing succeeds");
        assert_ne!(n1, n2, "two encryptions reused a nonce");
    }

    /// Two encryptions of the same plaintext must differ, otherwise they leak that the
    /// two contents are equal.
    #[test]
    fn ciphertext_is_not_deterministic() {
        let k = key();
        let id = EntryId::generate().expect("OS randomness available");
        let (_, c1) =
            seal(&k, RecordKind::Entry, id.as_bytes(), 1, b"same").expect("sealing succeeds");
        let (_, c2) =
            seal(&k, RecordKind::Entry, id.as_bytes(), 1, b"same").expect("sealing succeeds");
        assert_ne!(c1, c2);
    }

    /// Another master key must fail to decrypt.
    #[test]
    fn wrong_master_key_fails() {
        let id = EntryId::generate().expect("OS randomness available");
        let (nonce, ciphertext) =
            seal(&key(), RecordKind::Entry, id.as_bytes(), 1, b"secret").expect("sealing succeeds");
        let err = open(
            &key(),
            RecordKind::Entry,
            id.as_bytes(),
            1,
            &nonce,
            &ciphertext,
        );
        assert!(matches!(err, Err(Error::VaultDecryptionFailed)));
    }

    /// **Core AAD test**: ciphertext must not move between entries. It opens at its
    /// original position and fails at another `entry_id`.
    #[test]
    fn ciphertext_cannot_move_between_entry_ids() {
        let k = key();
        let a = EntryId::generate().expect("OS randomness available");
        let b = EntryId::generate().expect("OS randomness available");
        let (nonce, ciphertext) =
            seal(&k, RecordKind::Entry, a.as_bytes(), 1, b"payload").expect("sealing succeeds");

        assert!(open(&k, RecordKind::Entry, a.as_bytes(), 1, &nonce, &ciphertext).is_ok());

        let err = open(&k, RecordKind::Entry, b.as_bytes(), 1, &nonce, &ciphertext);
        assert!(
            matches!(err, Err(Error::VaultDecryptionFailed)),
            "the ciphertext was moved to another entry yet still opens"
        );
    }

    /// Ciphertext must not move between kinds (a tombstone impersonating an entry and
    /// the reverse).
    #[test]
    fn ciphertext_cannot_move_between_kinds() {
        let k = key();
        let id = EntryId::generate().expect("OS randomness available");

        let (nonce, ciphertext) =
            seal(&k, RecordKind::Entry, id.as_bytes(), 1, b"payload").expect("sealing succeeds");
        assert!(
            open(
                &k,
                RecordKind::Tombstone,
                id.as_bytes(),
                1,
                &nonce,
                &ciphertext
            )
            .is_err()
        );

        let (nonce2, ciphertext2) = seal(&k, RecordKind::Tombstone, id.as_bytes(), 1, b"payload")
            .expect("sealing succeeds");
        assert!(
            open(
                &k,
                RecordKind::Entry,
                id.as_bytes(),
                1,
                &nonce2,
                &ciphertext2
            )
            .is_err()
        );
    }

    /// Ciphertext must not move between format versions.
    #[test]
    fn ciphertext_cannot_move_between_format_versions() {
        let k = key();
        let id = EntryId::generate().expect("OS randomness available");
        let (nonce, ciphertext) =
            seal(&k, RecordKind::Entry, id.as_bytes(), 1, b"payload").expect("sealing succeeds");
        assert!(open(&k, RecordKind::Entry, id.as_bytes(), 2, &nonce, &ciphertext).is_err());
    }

    /// **Flipping any single byte of the ciphertext, the nonce or the tag must fail.**
    ///
    /// Every position is flipped, covering the ciphertext body, all 24 nonce bytes and
    /// the 16 tag bytes.
    #[test]
    fn flipping_any_ciphertext_byte_fails_authentication() {
        let k = key();
        let id = EntryId::generate().expect("OS randomness available");
        let plaintext = b"0123456789abcdef0123456789abcdef";
        let (nonce, ciphertext) =
            seal(&k, RecordKind::Entry, id.as_bytes(), 1, plaintext).expect("sealing succeeds");

        for index in 0..ciphertext.len() {
            let mut tampered = ciphertext.clone();
            tampered[index] ^= 0x01;
            let err = open(&k, RecordKind::Entry, id.as_bytes(), 1, &nonce, &tampered);
            assert!(
                matches!(err, Err(Error::VaultDecryptionFailed)),
                "ciphertext byte {index} was flipped yet still authenticates"
            );
        }

        for index in 0..NONCE_LEN {
            let mut tampered = nonce;
            tampered[index] ^= 0x01;
            let err = open(
                &k,
                RecordKind::Entry,
                id.as_bytes(),
                1,
                &tampered,
                &ciphertext,
            );
            assert!(
                matches!(err, Err(Error::VaultDecryptionFailed)),
                "nonce byte {index} was flipped yet still authenticates"
            );
        }
    }

    /// The AAD length and layout are a public contract (they define file semantics); the
    /// test pins them down.
    #[test]
    fn aad_layout_is_stable() {
        let id = EntryId::from_bytes([0xAB; EntryId::LEN]);
        let aad = build_aad(RecordKind::Entry, id.as_bytes(), 1);
        assert_eq!(aad.len(), AAD_LEN);
        assert_eq!(aad[0], 0x01, "kind byte");
        assert_eq!(&aad[1..17], &[0xAB; 16], "entry_id must follow immediately");
        assert_eq!(aad[17], 1, "the format version must be the last byte");

        assert_eq!(build_aad(RecordKind::Tombstone, id.as_bytes(), 7)[0], 0x02);
        assert_eq!(build_aad(RecordKind::Tombstone, id.as_bytes(), 7)[17], 7);
    }

    /// Kind bytes must round-trip and unknown values must be rejected.
    ///
    /// The bytes are written out literally: they are part of the AAD, so changing one makes
    /// every existing ciphertext of that kind undecryptable, and this test has to fail rather
    /// than follow the constant.
    #[test]
    fn record_kind_byte_roundtrips_and_rejects_unknown() {
        for (kind, byte) in [
            (RecordKind::Entry, 0x01),
            (RecordKind::Tombstone, 0x02),
            (RecordKind::Group, 0x03),
        ] {
            assert_eq!(
                kind.as_byte(),
                byte,
                "the file-format kind bytes are a contract"
            );
            assert_eq!(RecordKind::from_byte(byte), Some(kind));
        }
        for unknown in [0_u8, 4, 0xFF] {
            assert_eq!(RecordKind::from_byte(unknown), None);
        }
        for sync in [RecordKind::SyncEntry, RecordKind::SyncTombstone] {
            assert_eq!(
                RecordKind::from_byte(sync.as_byte()),
                None,
                "a sync kind must never be accepted inside a vault file"
            );
        }
    }

    /// Empty plaintext must round-trip too (boundary).
    #[test]
    fn empty_plaintext_roundtrips() {
        let k = key();
        let id = EntryId::generate().expect("OS randomness available");
        let (nonce, ciphertext) =
            seal(&k, RecordKind::Entry, id.as_bytes(), 1, b"").expect("sealing succeeds");
        assert_eq!(
            ciphertext.len(),
            TAG_LEN,
            "empty plaintext leaves only the tag"
        );
        let opened = open(&k, RecordKind::Entry, id.as_bytes(), 1, &nonce, &ciphertext)
            .expect("opening succeeds");
        assert!(opened.is_empty());
    }

    /// Truncated ciphertext must fail; an incomplete tag is not a valid short plaintext.
    #[test]
    fn truncated_ciphertext_fails() {
        let k = key();
        let id = EntryId::generate().expect("OS randomness available");
        let (nonce, ciphertext) =
            seal(&k, RecordKind::Entry, id.as_bytes(), 1, b"payload").expect("sealing succeeds");

        for cut in 1..=ciphertext.len() {
            let truncated = &ciphertext[..ciphertext.len() - cut];
            let err = open(&k, RecordKind::Entry, id.as_bytes(), 1, &nonce, truncated);
            assert!(
                matches!(err, Err(Error::VaultDecryptionFailed)),
                "truncating {cut} bytes still authenticates"
            );
        }
    }

    /// `master_key_to_bytes` must produce bytes that rebuild the same key.
    #[test]
    fn master_key_bytes_roundtrip() {
        let original =
            MasterKey::from_bytes(vec![9_u8; MASTER_KEY_LEN].into()).expect("correct length");
        let bytes = master_key_to_bytes(&original);
        let rebuilt = MasterKey::from_bytes(bytes).expect("correct length");
        assert_eq!(original.expose(), rebuilt.expose());
    }
}
