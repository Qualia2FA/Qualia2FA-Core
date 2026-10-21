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

//! Unlock password: wrapping the master key for the application lock.
//!
//! # What it is for
//!
//! [`crate::recovery`] backs the master key up so that it survives the loss of a
//! device. This module protects the **live** master key on a device: the file is kept
//! beside the vault, and opening the vault requires the user's unlock password.
//!
//! The two formats look alike but are not interchangeable. A recovery file is carried
//! to another machine and its passphrase is the only defence against a stolen copy; a
//! lock wrap never leaves the device and the platform authentication wrap (see the
//! `qualia-bioauth` crate) is the other way in.
//!
//! # Threat model
//!
//! A lock wrap protects against an attacker who has the device's files but not its
//! user: the vault file alone is not enough, because the master key is in the wrap.
//! What it cannot do is resist an attacker who can run code as the user and observe
//! the unlocked vault; that is outside any password scheme.
//!
//! The same Argon2id reasoning as [`crate::recovery`] applies: the password is
//! assumed weak, so derivation must be expensive, the parameters travel with the file
//! so old files stay readable, and the password enters [`SecretString`] as early as
//! possible. Parameters come from the file and are therefore untrusted: the bounds are
//! checked **before** Argon2id runs.
//!
//! # Domain separation
//!
//! The Argon2id input is a fixed context string followed by the password. The context
//! is not secret and is not stored in the file; it is part of this format. Consequently
//! a recovery file whose magic is rewritten to this format's still fails to open as a
//! lock wrap: it was wrapped under a different derived key. Conversely, a lock wrap can
//! never be restored as a recovery file.
//!
//! # File format
//!
//! ```text
//!   offset  length  content
//!   0       8       magic `Q2FAPW01`
//!   8       1       format version (1)
//!   9       1       algorithm identifier (1 = Argon2id v1.3)
//!   10      4       memory cost m_cost, KiB, big-endian
//!   14      4       iteration count t_cost, big-endian
//!   18      4       parallelism p_cost, big-endian
//!   22      16      salt (random)
//!   38      24      AEAD nonce (random)
//!   62      32      ciphertext of the master key
//!   94      16      AEAD tag
//!   ────────
//!   total   110 bytes
//! ```
//!
//! **Every header field from the format version onwards enters the AAD**; only the
//! magic is excluded, because it has to be read before any key exists. Changing a
//! parameter, the salt or the nonce therefore fails authentication rather than making
//! derivation cheaper.
//!
//! # Status
//!
//! Implemented: wrapping, unwrapping, header inspection and the parameter bounds. The
//! application files that track whether a lock is enabled (`lock.marker` and
//! `lock.pending`) are the application's business; this module holds no secrets for
//! them.

use crate::vault::{MASTER_KEY_LEN, MasterKey, NONCE_LEN, TAG_LEN};
use crate::{Error, ExposeSecret, Result, SecretBytes, SecretString};
use argon2::Params;
use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use secrecy::zeroize::Zeroize;

mod marker;

pub use marker::{LockMarker, LockPending, MARKER_LEN, PENDING_LEN, STATE_FORMAT_VERSION};

/// File magic.
///
/// Eight bytes, no NUL terminator: unlike the recovery file, this one is never typed or
/// printed, and the trailing NUL would only make it look like text.
const MAGIC: &[u8; 8] = b"Q2FAPW01";

/// Current format version.
pub const FORMAT_VERSION: u8 = 1;

/// Algorithm identifier: Argon2id v1.3.
const ALGORITHM_ARGON2ID_V13: u8 = 1;

/// Domain separator mixed into the Argon2id input.
///
/// The trailing NUL keeps the context from being a prefix of a longer one; it is not
/// part of the password.
const KDF_DOMAIN: &[u8] = b"Qualia2FA lock password v1\0";

/// Salt length, the same as [`crate::recovery::SALT_LEN`].
///
/// The value is repeated rather than re-exported because the two formats are allowed to
/// diverge; a change here must not silently change already-written recovery files.
const SALT_LEN: usize = 16;

/// Derivation key length, the same as the master key length.
const DERIVED_KEY_LEN: usize = crate::recovery::DERIVED_KEY_LEN;

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
    pub const CIPHERTEXT: usize = NONCE + super::NONCE_LEN;
    /// Start of the AAD (every header field from the format version on).
    pub const AAD: usize = VERSION;
    /// End of the AAD (just before the ciphertext).
    pub const AAD_END: usize = CIPHERTEXT;
}

/// Total length of a password-wrapped master key.
pub const FILE_LEN: usize = offset::CIPHERTEXT + MASTER_KEY_LEN + TAG_LEN;

/// The fixed-size header of a password wrap.
///
/// The salt and nonce are kept private: they are not secrets, but nothing outside this
/// module needs them, and a type that hands out nonces invites callers to reuse them.
#[derive(Clone, PartialEq, Eq)]
pub struct WrapHeader {
    /// Derivation parameters, already checked against the bounds.
    params: crate::recovery::KdfParams,
    /// Random salt.
    salt: [u8; SALT_LEN],
    /// Random AEAD nonce.
    nonce: [u8; NONCE_LEN],
}

impl core::fmt::Debug for WrapHeader {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("WrapHeader")
            .field("params", &self.params)
            .finish_non_exhaustive()
    }
}

impl WrapHeader {
    /// Parses and validates the header of a password wrap.
    ///
    /// This runs no key derivation, which makes it the cheap question a caller can ask
    /// before deciding to spend Argon2id time. It still rejects every structural problem
    /// and every out-of-range parameter.
    ///
    /// # Errors
    ///
    /// - wrong length or magic: [`Error::LockFileMalformed`]
    /// - unknown version or algorithm: [`Error::UnsupportedFormatVersion`]
    /// - parameters outside the bounds: [`Error::LockParametersInvalid`]
    pub fn parse(file: &[u8]) -> Result<Self> {
        if file.len() != FILE_LEN {
            return Err(Error::LockFileMalformed {
                reason: "the length is not the fixed password wrap length",
            });
        }
        if &file[offset::MAGIC..offset::VERSION] != MAGIC {
            return Err(Error::LockFileMalformed {
                reason: "magic mismatch: this is not a password-wrapped master key",
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
                .map_err(|_| Error::LockFileMalformed {
                    reason: "failed to read the memory cost field",
                })?,
        );
        let iterations = u32::from_be_bytes(
            file[offset::ITERATIONS..offset::ITERATIONS + 4]
                .try_into()
                .map_err(|_| Error::LockFileMalformed {
                    reason: "failed to read the iteration count field",
                })?,
        );
        let parallelism = u32::from_be_bytes(
            file[offset::PARALLELISM..offset::PARALLELISM + 4]
                .try_into()
                .map_err(|_| Error::LockFileMalformed {
                    reason: "failed to read the parallelism field",
                })?,
        );
        let params = checked_params(memory_kib, iterations, parallelism)?;

        let mut salt = [0_u8; SALT_LEN];
        salt.copy_from_slice(&file[offset::SALT..offset::SALT + SALT_LEN]);
        let mut nonce = [0_u8; NONCE_LEN];
        nonce.copy_from_slice(&file[offset::NONCE..offset::NONCE + NONCE_LEN]);

        Ok(Self {
            params,
            salt,
            nonce,
        })
    }

    /// The derivation parameters this file asks for.
    #[must_use]
    pub const fn params(&self) -> &crate::recovery::KdfParams {
        &self.params
    }
}

/// Validates parameters that came from a file.
///
/// The bounds are the same as [`crate::recovery`]'s: a file is untrusted input, and a
/// `m_cost` of `u32::MAX` must be one clear error rather than an allocation attempt.
fn checked_params(
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<crate::recovery::KdfParams> {
    if memory_kib < Params::MIN_M_COST {
        return Err(Error::LockParametersInvalid {
            reason: "the memory cost is below the Argon2 minimum",
        });
    }
    if memory_kib > crate::recovery::MAX_MEMORY_KIB {
        return Err(Error::LockParametersInvalid {
            reason: "the memory cost is above the maximum this implementation allows",
        });
    }
    if iterations < Params::MIN_T_COST {
        return Err(Error::LockParametersInvalid {
            reason: "the iteration count must not be zero",
        });
    }
    if iterations > crate::recovery::MAX_ITERATIONS {
        return Err(Error::LockParametersInvalid {
            reason: "the iteration count is above the maximum this implementation allows",
        });
    }
    if parallelism != crate::recovery::PARALLELISM {
        return Err(Error::LockParametersInvalid {
            reason: "this implementation only supports a parallelism of 1",
        });
    }
    crate::recovery::KdfParams::new(memory_kib, iterations, parallelism).map_err(|_| {
        Error::LockParametersInvalid {
            reason: "Argon2 rejected these parameters",
        }
    })
}

/// Wraps the master key with a password.
///
/// # Parameters
///
/// - `master`: the key to protect.
/// - `passphrase`: the unlock password. The caller reads it into [`SecretString`]; this
///   library does no I/O and never sees a bare `String`.
/// - `params`: derivation parameters. [`crate::recovery::KdfParams::recommended`] is
///   the normal choice.
///
/// # Returns
///
/// The complete file, always [`FILE_LEN`] bytes long. Where it is written is up to the
/// caller.
///
/// # Errors
///
/// - empty password: [`Error::LockPassphraseEmpty`]
/// - OS randomness unavailable: [`Error::RandomnessUnavailable`]
/// - Argon2 failure: [`Error::LockKdfFailed`]
/// - AEAD limit: [`Error::LockEncryptionFailed`]
///
/// **An empty password is rejected outright** rather than accepted as a very weak one:
/// accepting it would leave a lock that anybody can pass.
pub fn wrap(
    master: &MasterKey,
    passphrase: &SecretString,
    params: &crate::recovery::KdfParams,
) -> Result<Vec<u8>> {
    if passphrase.expose_secret().is_empty() {
        return Err(Error::LockPassphraseEmpty);
    }

    let mut salt = [0_u8; SALT_LEN];
    crate::getrandom::fill(&mut salt).map_err(|_| Error::RandomnessUnavailable)?;
    let mut nonce = [0_u8; NONCE_LEN];
    crate::getrandom::fill(&mut nonce).map_err(|_| Error::RandomnessUnavailable)?;

    let mut key = derive_key(passphrase, &salt, params)?;

    let mut file = Vec::with_capacity(FILE_LEN);
    file.extend_from_slice(MAGIC);
    file.push(FORMAT_VERSION);
    file.push(ALGORITHM_ARGON2ID_V13);
    file.extend_from_slice(&params.memory_kib().to_be_bytes());
    file.extend_from_slice(&params.iterations().to_be_bytes());
    file.extend_from_slice(&params.parallelism().to_be_bytes());
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
    if result.is_err() {
        ciphertext.zeroize();
        return Err(Error::LockEncryptionFailed);
    }

    file.extend_from_slice(&ciphertext);
    debug_assert_eq!(file.len(), FILE_LEN);
    Ok(file)
}

/// Recovers the master key from a password wrap.
///
/// # Errors
///
/// - empty password: [`Error::LockPassphraseEmpty`]
/// - wrong length or magic: [`Error::LockFileMalformed`]
/// - unknown version or algorithm: [`Error::UnsupportedFormatVersion`]
/// - parameters out of range: [`Error::LockParametersInvalid`]
/// - **wrong password or tampered file**: [`Error::LockPasswordRejected`]
/// - Argon2 failure: [`Error::LockKdfFailed`]
///
/// The last authentication case merges "wrong password" and "file was modified" on
/// purpose: separating them would give an attacker an oracle, and the user's response is
/// the same.
pub fn unwrap(file: &[u8], passphrase: &SecretString) -> Result<MasterKey> {
    if passphrase.expose_secret().is_empty() {
        return Err(Error::LockPassphraseEmpty);
    }

    let header = WrapHeader::parse(file)?;
    let mut key = derive_key(passphrase, &header.salt, &header.params)?;

    let mut plaintext = file[offset::CIPHERTEXT..].to_vec();
    let aad = file[offset::AAD..offset::AAD_END].to_vec();
    let result = XChaCha20Poly1305::new(&Key::from(key)).decrypt_in_place(
        &XNonce::from(header.nonce),
        &aad,
        &mut plaintext,
    );
    key.zeroize();
    if result.is_err() {
        plaintext.zeroize();
        return Err(Error::LockPasswordRejected);
    }

    let secret: SecretBytes = core::mem::take(&mut plaintext).into();
    MasterKey::from_bytes(secret)
}

/// Derives the wrap key with the lock's domain separator.
///
/// The caller wipes the returned key after use.
fn derive_key(
    passphrase: &SecretString,
    salt: &[u8; SALT_LEN],
    params: &crate::recovery::KdfParams,
) -> Result<[u8; DERIVED_KEY_LEN]> {
    crate::recovery::derive_key_with_context(KDF_DOMAIN, passphrase, salt, params)
        .map_err(|_| Error::LockKdfFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recovery::{KdfParams, export as export_recovery};

    /// **Minimal** parameters for tests, so the suite stays fast.
    fn fast_params() -> KdfParams {
        KdfParams::new(Params::MIN_M_COST, 1, 1).expect("the minimum parameters should be valid")
    }

    /// Builds a password.
    fn passphrase(text: &str) -> SecretString {
        SecretString::from(text)
    }

    /// Wraps a fresh master key with the given password and parameters.
    fn sample(text: &str) -> (MasterKey, Vec<u8>) {
        let master = MasterKey::generate().expect("randomness should be available");
        let file = wrap(&master, &passphrase(text), &fast_params()).expect("wrap should succeed");
        (master, file)
    }

    /// Wrapping and unwrapping restores the same master key.
    #[test]
    fn wrap_unwrap_roundtrip() {
        let (master, file) = sample("correct horse battery staple");
        assert_eq!(file.len(), FILE_LEN, "the file length must be constant");

        let restored = unwrap(&file, &passphrase("correct horse battery staple"))
            .expect("unwrap should succeed");
        assert_eq!(restored.expose(), master.expose());
    }

    /// **A wrong password must be rejected**, and reported as a password failure rather
    /// than as a malformed file.
    #[test]
    fn wrong_password_is_rejected() {
        let (_, file) = sample("right");
        assert!(matches!(
            unwrap(&file, &passphrase("wrong")),
            Err(Error::LockPasswordRejected)
        ));
    }

    /// An empty password is rejected at wrap time.
    #[test]
    fn empty_password_is_rejected_on_wrap() {
        let master = MasterKey::generate().expect("randomness should be available");
        assert!(matches!(
            wrap(&master, &passphrase(""), &fast_params()),
            Err(Error::LockPassphraseEmpty)
        ));
    }

    /// An empty password is rejected at unwrap time as well.
    #[test]
    fn empty_password_is_rejected_on_unwrap() {
        let (_, file) = sample("real password");
        assert!(matches!(
            unwrap(&file, &passphrase("")),
            Err(Error::LockPassphraseEmpty)
        ));
    }

    /// **Flipping any single byte must be detected.**
    #[test]
    fn any_single_byte_flip_is_detected() {
        let (master, file) = sample("tamper test");
        let phrase = passphrase("tamper test");

        for index in 0..FILE_LEN {
            let mut tampered = file.clone();
            tampered[index] ^= 0x01;
            match unwrap(&tampered, &phrase) {
                Err(_) => {}
                Ok(restored) => panic!(
                    "byte {index} was flipped but unwrap succeeded (restored key equals the original = {})",
                    restored.expose() == master.expose()
                ),
            }
        }
    }

    /// **Parameters are checked before Argon2id runs**, so an inflated cost is one clear
    /// error instead of an allocation attempt or a derivation that never ends.
    #[test]
    fn out_of_range_parameters_are_rejected_before_the_kdf() {
        let (_, file) = sample("parameter bomb");
        let phrase = passphrase("parameter bomb");

        for memory in [
            0_u32,
            1,
            Params::MIN_M_COST - 1,
            crate::recovery::MAX_MEMORY_KIB + 1,
            u32::MAX,
        ] {
            let mut tampered = file.clone();
            tampered[offset::MEMORY..offset::MEMORY + 4].copy_from_slice(&memory.to_be_bytes());
            assert!(
                matches!(
                    unwrap(&tampered, &phrase),
                    Err(Error::LockParametersInvalid { .. })
                ),
                "memory parameter {memory} must report invalid parameters"
            );
        }
        for iterations in [0_u32, crate::recovery::MAX_ITERATIONS + 1, u32::MAX] {
            let mut tampered = file.clone();
            tampered[offset::ITERATIONS..offset::ITERATIONS + 4]
                .copy_from_slice(&iterations.to_be_bytes());
            assert!(
                matches!(
                    unwrap(&tampered, &phrase),
                    Err(Error::LockParametersInvalid { .. })
                ),
                "iteration count {iterations} must report invalid parameters"
            );
        }
        for parallelism in [0_u32, 2, u32::MAX] {
            let mut tampered = file.clone();
            tampered[offset::PARALLELISM..offset::PARALLELISM + 4]
                .copy_from_slice(&parallelism.to_be_bytes());
            assert!(
                matches!(
                    unwrap(&tampered, &phrase),
                    Err(Error::LockParametersInvalid { .. })
                ),
                "parallelism {parallelism} must report invalid parameters"
            );
        }
    }

    /// Input of the wrong length is rejected and never panics.
    #[test]
    fn wrong_length_is_rejected() {
        let (_, file) = sample("length test");
        let phrase = passphrase("length test");

        for cut in [0_usize, 1, FILE_LEN - 1] {
            assert!(
                matches!(
                    unwrap(&file[..cut], &phrase),
                    Err(Error::LockFileMalformed { .. })
                ),
                "length {cut} must be rejected"
            );
        }
        let mut longer = file.clone();
        longer.push(0);
        assert!(matches!(
            unwrap(&longer, &phrase),
            Err(Error::LockFileMalformed { .. })
        ));
    }

    /// A wrong magic says "not a lock wrap", not "wrong password".
    #[test]
    fn wrong_magic_is_reported_as_malformed() {
        let (_, mut file) = sample("magic test");
        file[0] = b'X';
        assert!(matches!(
            unwrap(&file, &passphrase("magic test")),
            Err(Error::LockFileMalformed { .. })
        ));
    }

    /// A future version is rejected explicitly.
    #[test]
    fn unknown_version_is_rejected() {
        let (_, mut file) = sample("version test");
        file[offset::VERSION] = 0x7F;
        match unwrap(&file, &passphrase("version test")) {
            Err(Error::UnsupportedFormatVersion { version }) => assert_eq!(version, 0x7F),
            other => panic!(
                "an unsupported version should be reported, got is_ok={}",
                other.is_ok()
            ),
        }
    }

    /// An unknown algorithm is rejected as well.
    #[test]
    fn unknown_algorithm_is_rejected() {
        let (_, mut file) = sample("algorithm test");
        file[offset::ALGORITHM] = 0x7F;
        assert!(matches!(
            unwrap(&file, &passphrase("algorithm test")),
            Err(Error::UnsupportedFormatVersion { .. })
        ));
    }

    /// Two wraps of the same master key with the same password differ.
    #[test]
    fn same_password_yields_different_files() {
        let master = MasterKey::generate().expect("randomness should be available");
        let phrase = passphrase("same password");
        let a = wrap(&master, &phrase, &fast_params()).expect("wrap");
        let b = wrap(&master, &phrase, &fast_params()).expect("wrap");

        assert_ne!(a, b, "the salt or nonce was reused");
        assert_eq!(
            unwrap(&a, &phrase).expect("a").expose(),
            unwrap(&b, &phrase).expect("b").expose()
        );
    }

    /// The file never contains the master key in clear.
    #[test]
    fn file_never_contains_the_master_key_in_clear() {
        let (master, file) = sample("cleartext test");
        assert!(
            !file
                .windows(MASTER_KEY_LEN)
                .any(|window| window == master.expose()),
            "the password wrap contains the master key in clear"
        );
    }

    /// Parameters travel with the file.
    #[test]
    fn parameters_travel_with_the_file() {
        let master = MasterKey::generate().expect("randomness should be available");
        let phrase = passphrase("params travel");
        let params = KdfParams::new(Params::MIN_M_COST * 4, 2, 1).expect("valid parameters");
        let file = wrap(&master, &phrase, &params).expect("wrap");

        let header = WrapHeader::parse(&file).expect("the header should parse");
        assert_eq!(header.params().memory_kib(), params.memory_kib());
        assert_eq!(header.params().iterations(), params.iterations());
        assert_eq!(header.params().parallelism(), params.parallelism());
        assert_eq!(
            unwrap(&file, &phrase).expect("unwrap").expose(),
            master.expose()
        );
    }

    /// **The KDF domain separator makes the two formats non-interchangeable.**
    ///
    /// A recovery file and a password wrap have the same layout. Rewriting only the magic
    /// must not turn a backup into a lock wrap: the derived keys differ because recovery
    /// derives with an empty context and the lock with [`KDF_DOMAIN`].
    #[test]
    fn recovery_file_cannot_be_opened_as_a_lock_wrap() {
        let master = MasterKey::generate().expect("randomness should be available");
        let phrase = passphrase("domain separation");
        let mut recovery_file =
            export_recovery(&master, &phrase, &fast_params()).expect("recovery export");

        recovery_file[offset::MAGIC..offset::VERSION].copy_from_slice(MAGIC);

        assert!(matches!(
            unwrap(&recovery_file, &phrase),
            Err(Error::LockPasswordRejected)
        ));
    }

    /// A lock wrap cannot be restored as a recovery file either.
    #[test]
    fn lock_wrap_cannot_be_imported_as_a_recovery_file() {
        let (_, mut file) = sample("domain separation");
        file[offset::MAGIC..offset::VERSION].copy_from_slice(b"Q2FAREC\0");

        assert!(matches!(
            crate::recovery::import(&file, &passphrase("domain separation")),
            Err(Error::RecoveryAuthenticationFailed)
        ));
    }

    /// The file layout is a public contract: changing it invalidates every lock wrap
    /// already written.
    #[test]
    fn file_layout_is_stable() {
        assert_eq!(
            FILE_LEN, 110,
            "the password wrap length changed, which invalidates already-written files"
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

    /// The header parser is cheap and reports the parameters of a valid file.
    #[test]
    fn header_parse_accepts_a_wrap_and_reports_its_parameters() {
        let (_, file) = sample("header");
        let header = WrapHeader::parse(&file).expect("valid header");
        assert_eq!(header.params().memory_kib(), Params::MIN_M_COST);
        assert_eq!(header.params().iterations(), 1);
        assert_eq!(header.params().parallelism(), 1);
    }

    /// The debug form of a header carries the parameters and no salt or nonce.
    #[test]
    fn header_debug_does_not_print_the_salt_or_nonce() {
        let (_, file) = sample("debug");
        let header = WrapHeader::parse(&file).expect("valid header");
        let rendered = format!("{header:?}");
        assert!(rendered.contains("params"));
        assert!(!rendered.contains("salt"));
    }
}
