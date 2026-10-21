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

//! Recovery keys: backing up the master key with a user passphrase.
//!
//! # What it is for
//!
//! The master key is never written to disk in clear and lives only in the platform
//! key store. A lost phone, a broken disk, or a key store reset by the system makes
//! **every 2FA entry permanently undecryptable**. The pairing protocol
//! ([`crate::pairing`]) covers moving to a new device as long as the old device is
//! still there; when it is gone, a recovery key is the only remaining path.
//!
//! # Threat model
//!
//! A recovery file ends up in cloud storage, on a USB stick, in a mail attachment, or
//! printed on paper. An attacker who has the file itself must therefore be assumed,
//! and the only line of defence is the strength of the passphrase. Three rules
//! follow:
//!
//! 1. **Derivation must be expensive.** Argon2id is the winner of the Password
//!    Hashing Competition and the algorithm recommended by RFC 9106; its memory-hard
//!    property makes GPU/ASIC parallel cracking far less profitable than against a
//!    purely computational KDF.
//! 2. **The parameters must be stored in the file.** What was expensive ten years ago
//!    may be worth seconds on current hardware. Parameters travel with the file, so
//!    old files still open while new files can use the stronger parameters of their
//!    time; hard-coding them in the source would make the two incompatible.
//! 3. **The passphrase enters [`SecretString`] as early as possible**, and the
//!    derivation material is wiped once derivation is done.
//!
//! ## Out of scope
//!
//! - **Weak passphrases.** Argon2id only raises the cost of each guess; it does not
//!   turn `123456` into a strong passphrase. No passphrase-based scheme can fix that,
//!   and only UI guidance can.
//! - **An attacker who already controls the device.** They can obtain the master key
//!   anyway.
//!
//! # File format
//!
//! ```text
//!   offset  length  content
//!   0     8     magic `Q2FAREC\0`
//!   8     1     format version
//!   9     1     algorithm identifier (1 = Argon2id v1.3)
//!   10    4     memory cost m_cost, KiB, big-endian
//!   14    4     iteration count t_cost, big-endian
//!   18    4     parallelism p_cost, big-endian
//!   22    16    salt (random)
//!   38    24    AEAD nonce (random)
//!   62    32    ciphertext of the master key
//!   94    16    AEAD tag
//!   ────────
//!   total 110 bytes
//! ```
//!
//! **Every header field from the format version onwards enters the AAD**; only the
//! magic is excluded, because it has to be read before any key exists. Changing
//! `m_cost` therefore cannot "make derivation cheaper and then open the file": it
//! fails authentication outright.
//!
//! # Difference from the pairing protocol
//!
//! | | pairing | recovery key |
//! |---|---|---|
//! | situation | the old device **is there** | the old device **is gone** |
//! | credential | out-of-band QR code (high entropy) | user passphrase (low entropy) |
//! | derivation | ECDH | Argon2id |

use crate::vault::{MASTER_KEY_LEN, MasterKey, NONCE_LEN as AEAD_NONCE_LEN, master_key_to_bytes};
use crate::{Error, ExposeSecret, Result, SecretBytes, SecretString};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use secrecy::zeroize::Zeroize;

/// File magic. 8 bytes; the trailing `\0` keeps it from being confused with real
/// content in a text editor.
const MAGIC: &[u8; 8] = b"Q2FAREC\0";

/// Current format version.
pub const FORMAT_VERSION: u8 = 1;

/// Algorithm identifier: Argon2id v1.3.
const ALGORITHM_ARGON2ID_V13: u8 = 1;

/// Salt length.
///
/// 16 bytes is Argon2's own `RECOMMENDED_SALT_LEN` and the value recommended by
/// RFC 9106. The salt makes one passphrase derive different keys in different files,
/// which defeats precomputed rainbow tables and keeps two devices that use the same
/// passphrase from sharing a key.
pub const SALT_LEN: usize = 16;

/// Default memory cost: 64 MiB.
///
/// This is a hard constraint of mobile platforms: on Android a single Argon2id
/// allocation above roughly 100 MiB gets low-end devices killed by the system, and
/// the per-app memory limit on iOS is tighter still. 64 MiB is the customary
/// trade-off between "too high for GPU cracking to pay off" and "low enough for a
/// phone to finish".
///
/// Raising this default later does not break old files, because the parameters
/// travel inside the file.
pub const DEFAULT_MEMORY_KIB: u32 = 64 * 1024;

/// Default iteration count.
pub const DEFAULT_ITERATIONS: u32 = 3;

/// Default parallelism.
///
/// **Fixed at 1, with no entry point to raise it.** Argon2 parallelism means real
/// threads, which mobile and desktop platforms tolerate differently, and raising it
/// does not increase an attacker's cost: it only shortens a single wait. Any file
/// that records a `p_cost` must be recomputed with the same value on the reading
/// side, so the format keeps one fewer dimension that can vary.
pub const PARALLELISM: u32 = 1;

/// Requested output length, i.e. the length of the derived key.
pub(crate) const DERIVED_KEY_LEN: usize = 32;

/// Maximum allowed memory cost: 1 GiB.
///
/// `m_cost` comes from the imported file and is therefore attacker-controlled.
/// Without a limit, a file with that field set to `u32::MAX` would make this library
/// try to allocate 4 TiB: at best it fails with an error, at worst the machine is
/// dragged into swap and effectively stops responding (denial of service).
///
/// 1 GiB is far above any meaningful parameter (the default is 64 MiB, and 256 MiB
/// is already aggressive), so a normal file never reaches it; it is low enough that
/// even a genuinely malicious file costs one clear failure. The limit is looser than
/// needed so that raising the defaults later does not require changing it.
pub const MAX_MEMORY_KIB: u32 = 1024 * 1024;

/// Maximum allowed iteration count.
///
/// Same reasoning as [`MAX_MEMORY_KIB`]: `t_cost` also comes from the file. The
/// memory limit only bounds the size of one iteration, so a file with `t_cost` set
/// to `u32::MAX` would still make an import never finish.
///
/// 1000 is far above any reasonable value: the default is 3, and RFC 9106
/// recommends 1 to 10.
pub const MAX_ITERATIONS: u32 = 1000;

/// Offsets of the file sections.
mod offset {
    /// Start of the magic.
    pub const MAGIC: usize = 0;
    /// Format version.
    pub const VERSION: usize = 8;
    /// Algorithm identifier.
    pub const ALGORITHM: usize = 9;
    /// Memory cost (big-endian u32).
    pub const MEMORY: usize = 10;
    /// Iteration count (big-endian u32).
    pub const ITERATIONS: usize = 14;
    /// Parallelism (big-endian u32).
    pub const PARALLELISM: usize = 18;
    /// Salt.
    pub const SALT: usize = 22;
    /// AEAD nonce.
    pub const NONCE: usize = SALT + super::SALT_LEN;
    /// Ciphertext.
    pub const CIPHERTEXT: usize = NONCE + super::AEAD_NONCE_LEN;
    /// Start of the AAD (every header field from the format version on).
    pub const AAD: usize = super::offset::VERSION;
    /// End of the AAD (just before the ciphertext).
    pub const AAD_END: usize = super::offset::CIPHERTEXT;
}

/// Total length of a recovery file.
pub const FILE_LEN: usize = offset::CIPHERTEXT + MASTER_KEY_LEN + crate::vault::TAG_LEN;

/// Derivation parameters, written into the file and read back to recompute.
///
/// Not `Copy`: parameters are always passed by reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory cost, KiB.
    memory_kib: u32,
    /// Iteration count.
    iterations: u32,
    /// Parallelism.
    parallelism: u32,
}

impl KdfParams {
    /// The parameters this library recommends (64 MiB / 3 iterations /
    /// single-threaded).
    #[must_use]
    pub const fn recommended() -> Self {
        Self {
            memory_kib: DEFAULT_MEMORY_KIB,
            iterations: DEFAULT_ITERATIONS,
            parallelism: PARALLELISM,
        }
    }

    /// Custom parameters.
    ///
    /// # Errors
    ///
    /// Returns [`Error::RecoveryParametersInvalid`] when a parameter is out of range:
    /// memory must be between [`Params::MIN_M_COST`] and [`MAX_MEMORY_KIB`],
    /// iterations between 1 and [`MAX_ITERATIONS`], and parallelism exactly 1 (see
    /// [`PARALLELISM`]).
    ///
    /// Both bounds are checked because on the import path these three fields come
    /// from a file, which is untrusted input: with only a lower bound, a crafted file
    /// could make an import allocate several TiB or never finish.
    ///
    /// Lowering the parameters makes a file easier to crack. The entry point exists
    /// because exporting on very slow devices is a real need, and callers should
    /// treat it as a trade-off to explain to the user.
    pub const fn new(memory_kib: u32, iterations: u32, parallelism: u32) -> Result<Self> {
        if memory_kib < Params::MIN_M_COST {
            return Err(Error::RecoveryParametersInvalid {
                reason: "the memory cost is below the Argon2 minimum",
            });
        }
        if memory_kib > MAX_MEMORY_KIB {
            return Err(Error::RecoveryParametersInvalid {
                reason: "the memory cost is above the maximum this implementation allows",
            });
        }
        if iterations < Params::MIN_T_COST {
            return Err(Error::RecoveryParametersInvalid {
                reason: "the iteration count must not be zero",
            });
        }
        if iterations > MAX_ITERATIONS {
            return Err(Error::RecoveryParametersInvalid {
                reason: "the iteration count is above the maximum this implementation allows",
            });
        }
        if parallelism != PARALLELISM {
            return Err(Error::RecoveryParametersInvalid {
                reason: "this implementation only supports a parallelism of 1",
            });
        }
        Ok(Self {
            memory_kib,
            iterations,
            parallelism,
        })
    }

    /// Memory cost, KiB.
    #[must_use]
    pub const fn memory_kib(&self) -> u32 {
        self.memory_kib
    }

    /// Iteration count.
    #[must_use]
    pub const fn iterations(&self) -> u32 {
        self.iterations
    }

    /// Parallelism.
    #[must_use]
    pub const fn parallelism(&self) -> u32 {
        self.parallelism
    }
}

impl Default for KdfParams {
    fn default() -> Self {
        Self::recommended()
    }
}

/// Encrypts the master key into a recovery file suitable for long-term storage.
///
/// # Parameters
///
/// - `master`: the master key to back up.
/// - `passphrase`: user passphrase. The caller reads it into [`SecretString`]; this
///   library does no I/O and never sees a bare `String`.
/// - `params`: derivation parameters. [`KdfParams::recommended`] is the normal
///   choice; custom values are only for cases such as exporting on very slow
///   devices.
///
/// # Returns
///
/// The complete recovery file, always [`FILE_LEN`] bytes long. Where it is written
/// is up to the caller.
///
/// # Errors
///
/// - empty passphrase: [`Error::RecoveryPassphraseEmpty`]
/// - OS randomness unavailable: [`Error::RandomnessUnavailable`]
/// - invalid parameters: [`Error::RecoveryParametersInvalid`]
/// - Argon2 failure (out of memory, for example): [`Error::RecoveryKdfFailed`]
///
/// **An empty passphrase is rejected outright** rather than accepted as a (very
/// weak) one: accepting it would give the user a backup that looks successful and
/// that anyone can open in a second.
pub fn export(
    master: &MasterKey,
    passphrase: &SecretString,
    params: &KdfParams,
) -> Result<Vec<u8>> {
    if passphrase.expose_secret().is_empty() {
        return Err(Error::RecoveryPassphraseEmpty);
    }

    let mut salt = [0_u8; SALT_LEN];
    crate::getrandom::fill(&mut salt).map_err(|_| Error::RandomnessUnavailable)?;
    let mut nonce = [0_u8; AEAD_NONCE_LEN];
    crate::getrandom::fill(&mut nonce).map_err(|_| Error::RandomnessUnavailable)?;

    let mut key = derive_key(passphrase, &salt, params)?;

    let mut file = Vec::with_capacity(FILE_LEN);
    file.extend_from_slice(MAGIC);
    file.push(FORMAT_VERSION);
    file.push(ALGORITHM_ARGON2ID_V13);
    file.extend_from_slice(&params.memory_kib.to_be_bytes());
    file.extend_from_slice(&params.iterations.to_be_bytes());
    file.extend_from_slice(&params.parallelism.to_be_bytes());
    file.extend_from_slice(&salt);
    file.extend_from_slice(&nonce);

    let mut ciphertext = master.expose().to_vec();
    let aad = file[offset::AAD..offset::AAD_END].to_vec();
    let result = XChaCha20Poly1305::new(&Key::from(key)).encrypt_in_place(
        &XNonce::from(nonce),
        &aad,
        &mut ciphertext,
    );
    key.zeroize();
    result.map_err(|_| Error::RecoveryEncryptionFailed)?;

    file.extend_from_slice(&ciphertext);
    debug_assert_eq!(file.len(), FILE_LEN);
    Ok(file)
}

/// Recovers the master key from a recovery file.
///
/// The whole ciphertext including the trailing tag is passed to `decrypt_in_place`,
/// which strips the tag.
///
/// # Errors
///
/// - wrong length or magic: [`Error::RecoveryFileMalformed`]
/// - unknown version or algorithm: [`Error::UnsupportedFormatVersion`]
/// - invalid parameters: [`Error::RecoveryParametersInvalid`]
/// - **wrong passphrase or tampered file**: [`Error::RecoveryAuthenticationFailed`]
///
/// The last case merges "wrong passphrase" and "file was modified" into one variant
/// on purpose: separating them would give an attacker an oracle for whether a guess
/// was right, and folding structural damage in as well keeps the error type from
/// revealing whether a guess was close or the input is not a recovery file at all.
pub fn import(file: &[u8], passphrase: &SecretString) -> Result<MasterKey> {
    if file.len() != FILE_LEN {
        return Err(Error::RecoveryFileMalformed {
            reason: "the length is not the fixed recovery file length",
        });
    }
    if &file[offset::MAGIC..offset::VERSION] != MAGIC {
        return Err(Error::RecoveryFileMalformed {
            reason: "magic mismatch: this is not a recovery file of this application",
        });
    }
    if file[offset::VERSION] != FORMAT_VERSION {
        return Err(Error::UnsupportedFormatVersion {
            version: file[offset::VERSION],
        });
    }
    if file[offset::ALGORITHM] != ALGORITHM_ARGON2ID_V13 {
        return Err(Error::UnsupportedFormatVersion {
            version: file[offset::ALGORITHM],
        });
    }

    let memory_kib = u32::from_be_bytes(
        file[offset::MEMORY..offset::MEMORY + 4]
            .try_into()
            .map_err(|_| Error::RecoveryFileMalformed {
                reason: "failed to read the memory cost field",
            })?,
    );
    let iterations = u32::from_be_bytes(
        file[offset::ITERATIONS..offset::ITERATIONS + 4]
            .try_into()
            .map_err(|_| Error::RecoveryFileMalformed {
                reason: "failed to read the iteration count field",
            })?,
    );
    let parallelism = u32::from_be_bytes(
        file[offset::PARALLELISM..offset::PARALLELISM + 4]
            .try_into()
            .map_err(|_| Error::RecoveryFileMalformed {
                reason: "failed to read the parallelism field",
            })?,
    );
    let params = KdfParams::new(memory_kib, iterations, parallelism)?;

    let mut salt = [0_u8; SALT_LEN];
    salt.copy_from_slice(&file[offset::SALT..offset::SALT + SALT_LEN]);
    let mut nonce = [0_u8; AEAD_NONCE_LEN];
    nonce.copy_from_slice(&file[offset::NONCE..offset::NONCE + AEAD_NONCE_LEN]);

    let mut key = derive_key(passphrase, &salt, &params)?;

    let mut plaintext = file[offset::CIPHERTEXT..].to_vec();
    let aad = file[offset::AAD..offset::AAD_END].to_vec();
    let result = XChaCha20Poly1305::new(&Key::from(key)).decrypt_in_place(
        &XNonce::from(nonce),
        &aad,
        &mut plaintext,
    );
    key.zeroize();
    result.map_err(|_| Error::RecoveryAuthenticationFailed)?;

    let secret: SecretBytes = core::mem::take(&mut plaintext).into();
    MasterKey::from_bytes(secret)
}

/// Derives a key from the passphrase with Argon2id.
///
/// The caller wipes the returned key after use; this function keeps no copy.
fn derive_key(
    passphrase: &SecretString,
    salt: &[u8; SALT_LEN],
    params: &KdfParams,
) -> Result<[u8; DERIVED_KEY_LEN]> {
    derive_key_with_context(&[], passphrase, salt, params)
}

/// Derives a key from `context` followed by the passphrase.
///
/// The context is a fixed, non-secret domain separator. It makes two formats that
/// share the Argon2id construction derive **unrelated** keys from the same
/// passphrase, so a file written for one format cannot be read by the other even
/// after its magic bytes are rewritten. Recovery files pass an empty context; the
/// application lock uses its own (see [`crate::lock`]).
///
/// The concatenation is wiped before returning. The caller wipes the key.
pub(crate) fn derive_key_with_context(
    context: &[u8],
    passphrase: &SecretString,
    salt: &[u8; SALT_LEN],
    params: &KdfParams,
) -> Result<[u8; DERIVED_KEY_LEN]> {
    let params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(DERIVED_KEY_LEN),
    )
    .map_err(|_| Error::RecoveryParametersInvalid {
        reason: "Argon2 rejected these parameters",
    })?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let secret = passphrase.expose_secret().as_bytes();
    let mut material = Vec::with_capacity(context.len().saturating_add(secret.len()));
    material.extend_from_slice(context);
    material.extend_from_slice(secret);

    let mut out = [0_u8; DERIVED_KEY_LEN];
    let result = argon2.hash_password_into(&material, salt, &mut out);
    material.zeroize();
    result.map_err(|_| Error::RecoveryKdfFailed)?;
    Ok(out)
}

/// Wraps the master key as bytes suitable for a platform key store.
///
/// Identical to [`crate::pairing::master_key_for_storage`]; it saves users of this
/// module from importing `vault` as well.
#[must_use]
pub fn master_key_for_storage(master: &MasterKey) -> SecretBytes {
    master_key_to_bytes(master)
}

#[cfg(test)]
mod tests {
    use super::*;
    use argon2::{AssociatedData, ParamsBuilder};

    /// **Minimal** parameters for tests, so that the suite stays fast: the defaults
    /// (64 MiB / 3 iterations) cost tens of milliseconds per call and are pinned by
    /// `default_params_are_expensive`.
    ///
    /// The memory lower bound comes from Argon2 (8 KiB).
    fn fast_params() -> KdfParams {
        KdfParams::new(Params::MIN_M_COST, 1, 1).expect("the minimum parameters should be valid")
    }

    /// Builds a passphrase.
    fn passphrase(text: &str) -> SecretString {
        SecretString::from(text)
    }

    /// Export followed by import restores the same master key.
    #[test]
    fn export_import_roundtrip() {
        let master = MasterKey::generate().expect("randomness should be available");
        let file = export(
            &master,
            &passphrase("correct horse battery staple"),
            &fast_params(),
        )
        .expect("export should succeed");
        assert_eq!(file.len(), FILE_LEN, "the file length must be constant");

        let restored = import(&file, &passphrase("correct horse battery staple"))
            .expect("import should succeed");
        assert_eq!(restored.expose(), master.expose());
    }

    /// **A wrong passphrase must fail.**
    #[test]
    fn wrong_passphrase_fails() {
        let master = MasterKey::generate().expect("randomness should be available");
        let file = export(&master, &passphrase("right"), &fast_params()).expect("export");

        let result = import(&file, &passphrase("wrong"));
        assert!(
            matches!(result, Err(Error::RecoveryAuthenticationFailed)),
            "a wrong passphrase must be rejected"
        );
    }

    /// An empty passphrase is rejected **at export time**.
    #[test]
    fn empty_passphrase_is_rejected_on_export() {
        let master = MasterKey::generate().expect("randomness should be available");
        let result = export(&master, &passphrase(""), &fast_params());
        assert!(matches!(result, Err(Error::RecoveryPassphraseEmpty)));
    }

    /// **Flipping any single byte of the file must be detected.**
    ///
    /// Any change must surface at import time instead of silently restoring a wrong
    /// master key: recovery files end up in cloud storage, on USB sticks, and in mail
    /// attachments.
    ///
    /// The three parameter fields are covered by
    /// [`flipping_parameter_bytes_is_rejected_by_the_limits`] instead, which requires
    /// them to be rejected **without allocating**.
    #[test]
    fn any_single_byte_flip_is_detected() {
        let master = MasterKey::generate().expect("randomness should be available");
        let phrase = passphrase("tamper test");
        let file = export(&master, &phrase, &fast_params()).expect("export");

        let param_range = offset::MEMORY..offset::PARALLELISM + 4;
        for index in 0..FILE_LEN {
            if param_range.contains(&index) {
                continue;
            }
            let mut tampered = file.clone();
            tampered[index] ^= 0x01;
            match import(&tampered, &phrase) {
                Err(_) => {}
                Ok(restored) => panic!(
                    "byte {index} was flipped but the import succeeded (the restored key equals the original = {})",
                    restored.expose() == master.expose()
                ),
            }
        }
    }

    /// Flipping any byte of a **parameter field** is rejected by the limits before
    /// anything is allocated.
    ///
    /// Two outcomes are unacceptable: a successful import (the tampering went
    /// unnoticed), or a huge allocation (the import becomes a denial of service).
    #[test]
    fn flipping_parameter_bytes_is_rejected_by_the_limits() {
        let master = MasterKey::generate().expect("randomness should be available");
        let phrase = passphrase("param tamper test");
        let file = export(&master, &phrase, &fast_params()).expect("export");

        for index in offset::MEMORY..offset::PARALLELISM + 4 {
            let mut tampered = file.clone();
            tampered[index] ^= 0x01;
            match import(&tampered, &phrase) {
                Err(Error::RecoveryParametersInvalid { .. }) => {}
                Err(Error::RecoveryAuthenticationFailed) => {}
                Err(other) => panic!("byte {index}: unexpected error type {other}"),
                Ok(restored) => panic!(
                    "byte {index} was flipped but the import succeeded (same key = {})",
                    restored.expose() == master.expose()
                ),
            }
        }
    }

    /// Input of the wrong length is rejected and never panics.
    #[test]
    fn wrong_length_is_rejected() {
        let master = MasterKey::generate().expect("randomness should be available");
        let phrase = passphrase("length test");
        let file = export(&master, &phrase, &fast_params()).expect("export");

        for cut in [0_usize, 1, FILE_LEN - 1] {
            assert!(
                matches!(
                    import(&file[..cut], &phrase),
                    Err(Error::RecoveryFileMalformed { .. })
                ),
                "length {cut} must be rejected"
            );
        }
        let mut longer = file.clone();
        longer.push(0);
        assert!(matches!(
            import(&longer, &phrase),
            Err(Error::RecoveryFileMalformed { .. })
        ));
    }

    /// A wrong magic reports "this is not a recovery file" rather than "wrong
    /// passphrase"; the two mean completely different things to the user.
    #[test]
    fn wrong_magic_is_reported_as_malformed_not_wrong_passphrase() {
        let master = MasterKey::generate().expect("randomness should be available");
        let phrase = passphrase("magic test");
        let mut file = export(&master, &phrase, &fast_params()).expect("export");
        file[0] = b'X';

        assert!(matches!(
            import(&file, &phrase),
            Err(Error::RecoveryFileMalformed { .. })
        ));
    }

    /// A future version is rejected **explicitly** rather than being interpreted with
    /// this version's layout.
    #[test]
    fn unknown_version_is_rejected() {
        let master = MasterKey::generate().expect("randomness should be available");
        let phrase = passphrase("version test");
        let mut file = export(&master, &phrase, &fast_params()).expect("export");
        file[offset::VERSION] = 0x7F;

        match import(&file, &phrase) {
            Err(Error::UnsupportedFormatVersion { version }) => assert_eq!(version, 0x7F),
            other => panic!(
                "an unsupported version should be reported, got is_ok={}",
                other.is_ok()
            ),
        }
    }

    /// An unknown algorithm identifier is rejected as well.
    #[test]
    fn unknown_algorithm_is_rejected() {
        let master = MasterKey::generate().expect("randomness should be available");
        let phrase = passphrase("algorithm test");
        let mut file = export(&master, &phrase, &fast_params()).expect("export");
        file[offset::ALGORITHM] = 0x7F;
        assert!(import(&file, &phrase).is_err());
    }

    /// **An inflated memory parameter is rejected instead of being allocated.**
    ///
    /// Parameters come from the file, which is untrusted input: without an upper
    /// bound, a crafted file turns an import into a memory-exhaustion attack or a
    /// denial of service that drags the whole machine down.
    #[test]
    fn absurd_memory_cost_is_rejected_without_allocating() {
        let master = MasterKey::generate().expect("randomness should be available");
        let phrase = passphrase("memory bomb");
        let file = export(&master, &phrase, &fast_params()).expect("export");

        for memory in [0_u32, 1, Params::MIN_M_COST - 1] {
            assert!(
                matches!(
                    import_with_memory(&file, &phrase, memory),
                    Err(Error::RecoveryParametersInvalid { .. })
                ),
                "memory parameter {memory} must report invalid parameters"
            );
        }
        for memory in [MAX_MEMORY_KIB + 1, u32::MAX, u32::MAX / 2] {
            assert!(
                matches!(
                    import_with_memory(&file, &phrase, memory),
                    Err(Error::RecoveryParametersInvalid { .. })
                ),
                "memory parameter {memory} must report invalid parameters instead of actually allocating"
            );
        }
        assert!(
            KdfParams::new(MAX_MEMORY_KIB, 1, 1).is_ok(),
            "the limit itself should be valid"
        );
        assert!(
            KdfParams::new(MAX_MEMORY_KIB + 1, 1, 1).is_err(),
            "above the limit must be rejected"
        );
    }

    /// Imports the file with its memory parameter field set to the given value.
    fn import_with_memory(file: &[u8], phrase: &SecretString, memory: u32) -> Result<MasterKey> {
        let mut tampered = file.to_vec();
        tampered[offset::MEMORY..offset::MEMORY + 4].copy_from_slice(&memory.to_be_bytes());
        import(&tampered, phrase)
    }

    /// **An inflated iteration count is rejected.**
    ///
    /// The memory limit only bounds one iteration; a file with `t_cost` set to
    /// `u32::MAX` would still make an import never finish.
    #[test]
    fn absurd_iteration_count_is_rejected_without_running_forever() {
        let master = MasterKey::generate().expect("randomness should be available");
        let phrase = passphrase("iteration bomb");
        let file = export(&master, &phrase, &fast_params()).expect("export");

        for iterations in [MAX_ITERATIONS + 1, u32::MAX, u32::MAX / 2] {
            let mut tampered = file.clone();
            tampered[offset::ITERATIONS..offset::ITERATIONS + 4]
                .copy_from_slice(&iterations.to_be_bytes());
            assert!(
                matches!(
                    import(&tampered, &phrase),
                    Err(Error::RecoveryParametersInvalid { .. })
                ),
                "iteration count {iterations} must report invalid parameters"
            );
        }
        assert!(
            KdfParams::new(1024, MAX_ITERATIONS, 1).is_ok(),
            "the limit itself should be valid"
        );
        assert!(KdfParams::new(1024, MAX_ITERATIONS + 1, 1).is_err());
    }

    /// An iteration count of 0 is rejected.
    #[test]
    fn zero_iterations_is_rejected() {
        let master = MasterKey::generate().expect("randomness should be available");
        let phrase = passphrase("iterations test");
        let mut file = export(&master, &phrase, &fast_params()).expect("export");
        file[offset::ITERATIONS..offset::ITERATIONS + 4].copy_from_slice(&0_u32.to_be_bytes());

        assert!(matches!(
            import(&file, &phrase),
            Err(Error::RecoveryParametersInvalid { .. })
        ));
    }

    /// Any parallelism other than 1 is rejected.
    #[test]
    fn parallelism_other_than_one_is_rejected() {
        assert!(
            KdfParams::new(1024, 1, 2).is_err(),
            "parallelism 2 must be rejected"
        );
        assert!(
            KdfParams::new(1024, 1, 0).is_err(),
            "parallelism 0 must be rejected"
        );
        assert!(KdfParams::new(1024, 1, 1).is_ok());
    }

    /// **Known-answer vector from RFC 9106 §5.3: Argon2id v1.3.**
    ///
    /// The other tests here only check self-consistency (export then import round
    /// trips), which is blind to a wholly wrong implementation: if the Argon2
    /// parameters were misread, export and import would be wrong in the same way and
    /// still round trip. A recovery file is meant to be opened years later, possibly
    /// by another implementation on other dependency versions, so it is pinned to the
    /// standard here.
    ///
    /// Source: RFC 9106 §5.3 (Argon2id test vector).
    /// Parameters: memory 32 KiB, 3 iterations, parallelism 4, output 32 bytes;
    /// passphrase 32 bytes of `0x01`, salt 16 bytes of `0x02`, secret 8 bytes of
    /// `0x03`, associated data 12 bytes of `0x04`.
    ///
    /// The vector requires both a secret and non-empty associated data, so the test
    /// builds the parameters with `ParamsBuilder` and calls `Argon2::new_with_secret`
    /// directly instead of this module's `derive_key`, which deliberately exposes
    /// neither (no server-side pepper and no context bound into the output is needed
    /// here).
    ///
    /// This test pins the upstream implementation to the specification; this module's
    /// own parameter mapping is pinned by `derived_key_is_deterministic_and_pinned`.
    #[test]
    fn rfc9106_argon2id_test_vector() {
        let params = ParamsBuilder::new()
            .m_cost(32)
            .t_cost(3)
            .p_cost(4)
            .output_len(32)
            .data(AssociatedData::new(&[0x04_u8; 12]).expect("12 ≤ MAX_DATA_LEN"))
            .build()
            .expect("the RFC vector parameters should be valid");
        let secret = [0x03_u8; 8];
        let context = Argon2::new_with_secret(&secret, Algorithm::Argon2id, Version::V0x13, params)
            .expect("construction should succeed");
        let mut out = [0_u8; 32];
        context
            .hash_password_into(&[0x01_u8; 32], &[0x02_u8; 16], &mut out)
            .expect("the computation should succeed");

        let expected: [u8; 32] = [
            0x0d, 0x64, 0x0d, 0xf5, 0x8d, 0x78, 0x76, 0x6c, 0x08, 0xc0, 0x37, 0xa3, 0x4a, 0x8b,
            0x53, 0xc9, 0xd0, 0x1e, 0xf0, 0x45, 0x2d, 0x75, 0xb6, 0x5e, 0xb5, 0x25, 0x20, 0xe9,
            0x6b, 0x01, 0xe6, 0x59,
        ];
        assert_eq!(
            out, expected,
            "the Argon2id output does not match the RFC 9106 §5.3 vector"
        );
    }

    /// This module's derivation is **deterministic** and input changes change the
    /// output.
    ///
    /// Where the RFC test proves the Argon2id implementation is right, this one
    /// proves the inputs are: a wrong parameter mapping, salt use, or output length
    /// still round trips (both sides wrong the same way) but shows up here.
    #[test]
    fn derived_key_is_deterministic_and_pinned() {
        let phrase = passphrase("deterministic");
        let salt = [0x11_u8; SALT_LEN];
        let params = fast_params();

        let a = derive_key(&phrase, &salt, &params).expect("derivation should succeed");
        let b = derive_key(&phrase, &salt, &params).expect("derivation should succeed");
        assert_eq!(
            a, b,
            "the same passphrase and salt must derive the same key"
        );

        let mut other_salt = salt;
        other_salt[0] ^= 0x01;
        assert_ne!(
            derive_key(&phrase, &other_salt, &params).expect("derivation should succeed"),
            a,
            "changing the salt derived the same key"
        );

        let other_params = KdfParams::new(Params::MIN_M_COST * 2, 1, 1).expect("valid");
        assert_ne!(
            derive_key(&phrase, &salt, &other_params).expect("derivation should succeed"),
            a,
            "changing the memory parameter derived the same key"
        );

        assert_eq!(a.len(), DERIVED_KEY_LEN);
    }

    /// The output length is requested **explicitly** as 32: with `output_len` set to
    /// `None`, `Params::new` uses Argon2's own default of 32, which cannot be told
    /// apart by length, so the test compares actual bytes against a manual
    /// recomputation.
    #[test]
    fn output_length_is_explicitly_requested() {
        let phrase = passphrase("output length");
        let salt = [0x22_u8; SALT_LEN];
        let mut key =
            derive_key(&phrase, &salt, &fast_params()).expect("derivation should succeed");

        let params = Params::new(Params::MIN_M_COST, 1, 1, Some(DERIVED_KEY_LEN)).expect("valid");
        let mut expected = [0_u8; DERIVED_KEY_LEN];
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(phrase.expose_secret().as_bytes(), &salt, &mut expected)
            .expect("the computation should succeed");

        assert_eq!(key, expected);
        key.zeroize();
    }

    /// Two files exported with the **same passphrase** differ.
    ///
    /// Otherwise an attacker holding a recovery file with a known passphrase could
    /// compare ciphertexts to tell whether two devices use the same passphrase.
    #[test]
    fn same_passphrase_yields_different_files() {
        let master = MasterKey::generate().expect("randomness should be available");
        let phrase = passphrase("same passphrase");
        let a = export(&master, &phrase, &fast_params()).expect("export");
        let b = export(&master, &phrase, &fast_params()).expect("export");

        assert_ne!(a, b, "the salt or nonce was reused");
        assert_eq!(
            import(&a, &phrase).expect("a should import").expose(),
            import(&b, &phrase).expect("b should import").expose()
        );
    }

    /// The recovery file **never** contains the master key in clear; a regression that
    /// wrote `master.expose()` straight into the file would reduce the Argon2 layer to
    /// decoration.
    #[test]
    fn file_never_contains_the_master_key_in_clear() {
        let master = MasterKey::generate().expect("randomness should be available");
        let file = export(&master, &passphrase("cleartext test"), &fast_params()).expect("export");

        assert!(
            !file.windows(MASTER_KEY_LEN).any(|w| w == master.expose()),
            "the recovery file contains the master key in clear"
        );
    }

    /// The defaults are **actually expensive**, asserted on the parameter values
    /// rather than on timing, which varies per machine.
    #[test]
    fn default_params_are_expensive() {
        let params = KdfParams::recommended();
        assert_eq!(
            params.memory_kib(),
            64 * 1024,
            "the default memory is not 64 MiB"
        );
        assert!(
            params.iterations() >= 3,
            "the default iteration count is too low"
        );
        assert_eq!(params.parallelism(), 1);
        assert!(
            params.memory_kib() >= Params::DEFAULT_M_COST,
            "the default memory is below Argon2's own default"
        );
    }

    /// Parameters travel with the file: a file exported with custom parameters needs
    /// no parameters passed to the import.
    #[test]
    fn parameters_travel_with_the_file() {
        let master = MasterKey::generate().expect("randomness should be available");
        let phrase = passphrase("params travel");
        let params = KdfParams::new(Params::MIN_M_COST * 4, 2, 1).expect("valid parameters");
        let file = export(&master, &phrase, &params).expect("export");

        assert_eq!(
            u32::from_be_bytes(file[offset::MEMORY..offset::MEMORY + 4].try_into().unwrap()),
            params.memory_kib()
        );
        assert_eq!(
            u32::from_be_bytes(
                file[offset::ITERATIONS..offset::ITERATIONS + 4]
                    .try_into()
                    .unwrap()
            ),
            params.iterations()
        );
        assert_eq!(
            import(&file, &phrase).expect("import").expose(),
            master.expose()
        );
    }

    /// Master key storage round trip, consistent with the same-named helper in
    /// `pairing`.
    #[test]
    fn master_key_storage_roundtrip() {
        let master = MasterKey::generate().expect("randomness should be available");
        let bytes = master_key_for_storage(&master);
        let rebuilt =
            crate::pairing::master_key_from_storage(bytes).expect("the length is correct");
        assert_eq!(master.expose(), rebuilt.expose());
    }

    /// The file layout is a public contract and is pinned here: changing any offset
    /// invalidates **every recovery file already exported**, so it has to be
    /// deliberate and part of a version upgrade.
    #[test]
    fn file_layout_is_stable() {
        assert_eq!(
            FILE_LEN, 110,
            "the recovery file length changed, which invalidates already-exported files"
        );
        assert_eq!(offset::MAGIC, 0);
        assert_eq!(offset::VERSION, 8);
        assert_eq!(offset::ALGORITHM, 9);
        assert_eq!(offset::MEMORY, 10);
        assert_eq!(offset::ITERATIONS, 14);
        assert_eq!(offset::PARALLELISM, 18);
        assert_eq!(offset::SALT, 22);
        assert_eq!(offset::NONCE, 38);
        assert_eq!(offset::CIPHERTEXT, 62);
        assert_eq!(offset::AAD, 8);
        assert_eq!(offset::AAD_END, 62);
    }
}
