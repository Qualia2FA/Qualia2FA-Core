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

//! Portable vault containers: the master key and the vault ciphertext in one file.
//!
//! # Why a second container exists
//!
//! A vault file is useless without its master key, and the master key is useless without the
//! vault. A backup that carries one but not the other cannot restore an account on a clean
//! device. This module defines the two `.q2fa` containers that carry both, plus the old file
//! shape that carried only the key.
//!
//! ```text
//! plain      "Q2FAKEY1" (8) | version 1 (1) | reserved 0 (1)
//!            | master key (32) | vault length (4, BE) | vault file bytes
//!
//! encrypted  "Q2FABK01" (8) | version 1 (1)
//!            | recovery length (4, BE) | vault length (4, BE)
//!            | recovery file bytes | vault file bytes
//!
//! key-only   "Q2FAREC\0" (8) | … 102 more bytes (the core recovery file)
//! ```
//!
//! # The plain container is **not** protected
//!
//! Whoever holds the file holds the master key: that is what makes it restore an account on a
//! device that has nothing. It has no passphrase, no algorithm and no integrity check beyond
//! the lengths, and the interface must say so more strongly than it does for the encrypted form.
//! The encrypted container is the same pair with the master key wrapped by
//! [`crate::recovery`] (Argon2id + XChaCha20-Poly1305), so a passphrase is required to open it.
//!
//! # Nothing here is a new cryptographic shape
//!
//! The plain container simply writes the bytes of the two values; the encrypted one wraps the
//! master key with the existing recovery format and carries the vault ciphertext beside it.
//! Neither invents an algorithm, and both are means of **transport**: after they are opened the
//! vault is parsed by [`crate::vault::VaultFile::parse`] as usual, which is what decides whether
//! the pair actually belongs together.
//!
//! # Lengths are attacker-controlled
//!
//! Every length is read from the file, so each is compared against a limit **before** it is
//! used to allocate or slice, and the total length must equal exactly what the two lengths add
//! up to. Trailing bytes are refused rather than ignored: they mean the file was appended to or
//! assembled from parts, and reading only the first part would hide that.

use crate::vault::{MASTER_KEY_LEN, MasterKey, master_key_to_bytes};
use crate::{Error, ExposeSecret, Result, SecretBytes};

/// Magic of the **plain** container: the master key in clear plus the vault.
pub const PLAIN_MAGIC: &[u8; 8] = b"Q2FAKEY1";

/// Magic of the **passphrase-protected** container.
pub const ENCRYPTED_MAGIC: &[u8; 8] = b"Q2FABK01";

/// Magic of the old key-only recovery file, written by the first release of the restore screen.
pub const KEY_ONLY_MAGIC: &[u8; 8] = b"Q2FAREC\0";

/// Magic of a bare vault file, which carries **no** master key.
///
/// Recognized only to refuse it with a specific diagnosis; this module never reads one.
const VAULT_MAGIC: &[u8; 8] = b"Q2FAVLT\0";

/// The only container version this build writes and reads.
pub const VERSION: u8 = 1;

/// Header length of the plain container: magic + version + reserved + master key + length.
pub const PLAIN_HEADER_LEN: usize = 8 + 1 + 1 + MASTER_KEY_LEN + 4;

/// Header length of the encrypted container: magic + version + two lengths.
pub const ENCRYPTED_HEADER_LEN: usize = 8 + 1 + 4 + 4;

/// Largest vault payload accepted from a container: 64 MiB.
///
/// The same bound the import path applies to any file; a container's length field is
/// attacker-controlled, and a small header claiming gigabytes must not become an allocation.
pub const MAX_VAULT_BYTES: usize = 64 * 1024 * 1024;

/// Largest recovery payload accepted inside an encrypted container.
///
/// The core recovery file is 110 bytes; the slack allows a future format with larger KDF
/// parameters or a bigger salt without changing this container.
pub const MAX_RECOVERY_BYTES: usize = 4 * 1024;

/// What a file turned out to be, judged by its magic alone.
///
/// Names only: this says nothing about whether the contents are valid. A caller asks for a
/// passphrase on [`PortableKind::EncryptedVault`] **before** calling
/// [`crate::flow::open_portable`], so the password
/// question appears where it belongs instead of after a failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortableKind {
    /// The master key in clear plus the vault ciphertext.
    PlainVault,
    /// The master key wrapped by a passphrase plus the vault ciphertext.
    EncryptedVault,
    /// The old key-only recovery file: no entries, and useless without a local vault.
    KeyOnly,
}

impl PortableKind {
    /// Whether opening this kind needs a passphrase.
    #[must_use]
    pub const fn needs_password(self) -> bool {
        matches!(self, Self::EncryptedVault)
    }

    /// The name used in messages and diagnostics.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::PlainVault => "plain vault",
            Self::EncryptedVault => "encrypted vault",
            Self::KeyOnly => "key-only recovery file",
        }
    }
}

/// A container that has been split into its parts, still unauthenticated.
#[derive(Debug)]
pub enum PortableFile {
    /// A plain container: the master key bytes and the vault ciphertext.
    ///
    /// The key is held in [`SecretBytes`], which is erased when the value is dropped and prints
    /// as redacted in `Debug`.
    PlainVault {
        /// The 32-byte master key.
        master_key: SecretBytes,
        /// The vault file bytes.
        vault: Vec<u8>,
    },
    /// An encrypted container: the core recovery file and the vault ciphertext.
    EncryptedVault {
        /// The bytes of the core recovery file.
        recovery: Vec<u8>,
        /// The vault file bytes.
        vault: Vec<u8>,
    },
    /// The old key-only file: the core recovery file on its own.
    KeyOnly {
        /// The bytes of the core recovery file.
        recovery: Vec<u8>,
    },
}

impl PortableFile {
    /// The kind of container this was parsed from.
    #[must_use]
    pub const fn kind(&self) -> PortableKind {
        match self {
            Self::PlainVault { .. } => PortableKind::PlainVault,
            Self::EncryptedVault { .. } => PortableKind::EncryptedVault,
            Self::KeyOnly { .. } => PortableKind::KeyOnly,
        }
    }

    /// The vault bytes the container carries, when it carries any.
    #[must_use]
    pub fn vault(&self) -> Option<&[u8]> {
        match self {
            Self::PlainVault { vault, .. } | Self::EncryptedVault { vault, .. } => Some(vault),
            Self::KeyOnly { .. } => None,
        }
    }
}

/// Recognizes a container by its magic.
///
/// # A bare vault file is **not** a portable container
///
/// It answers `None` here and [`Error::PortableVaultFileWithoutKey`] from [`crate::flow::open_portable`]: the file
/// holds ciphertext but no key, so importing it would replace the local vault with data the
/// local key probably cannot open. The caller can tell the user what to export instead.
#[must_use]
pub fn detect(file: &[u8]) -> Option<PortableKind> {
    let magic = file.get(..8)?;
    if magic == PLAIN_MAGIC {
        Some(PortableKind::PlainVault)
    } else if magic == ENCRYPTED_MAGIC {
        Some(PortableKind::EncryptedVault)
    } else if magic == KEY_ONLY_MAGIC {
        Some(PortableKind::KeyOnly)
    } else {
        None
    }
}

/// Whether the file looks like a portable container of any kind.
#[must_use]
pub fn is_portable(file: &[u8]) -> bool {
    detect(file).is_some()
}

/// Splits a container into its parts.
///
/// No cryptographic check happens here; that is `flow::open_portable`'s business. What is
/// checked is the structure: the magic, the version, the reserved byte, both lengths and that
/// the total length is exactly what the header declares.
///
/// # Errors
///
/// - [`Error::PortableBadMagic`]: not one of the three magics.
/// - [`Error::PortableUnsupportedVersion`]: a container version this build does not read.
/// - [`Error::PortableTruncated`]: shorter than its header.
/// - [`Error::PortableTooLarge`]: a declared payload exceeds its limit.
/// - [`Error::PortableLengthMismatch`]: the two lengths do not add up to the file length.
/// - [`Error::PortableVaultFileWithoutKey`]: a bare vault file.
pub fn parse(file: &[u8]) -> Result<PortableFile> {
    let magic = file.get(..8).ok_or(Error::PortableTruncated)?;
    if magic == KEY_ONLY_MAGIC {
        // The recovery module owns this layout and its length checks; wrapping it here would
        // duplicate them and eventually disagree.
        return Ok(PortableFile::KeyOnly {
            recovery: file.to_vec(),
        });
    }
    if magic == VAULT_MAGIC {
        return Err(Error::PortableVaultFileWithoutKey);
    }
    if magic == PLAIN_MAGIC {
        return parse_plain(file);
    }
    if magic == ENCRYPTED_MAGIC {
        return parse_encrypted(file);
    }
    Err(Error::PortableBadMagic)
}

/// Parses the plain container.
fn parse_plain(file: &[u8]) -> Result<PortableFile> {
    if file.len() < PLAIN_HEADER_LEN {
        return Err(Error::PortableTruncated);
    }
    check_version(file[8])?;
    if file[9] != 0 {
        // Reserved for a future extension; a non-zero value must not be read as zero.
        return Err(Error::PortableBadMagic);
    }
    let master_key = SecretBytes::from(file[10..10 + MASTER_KEY_LEN].to_vec());
    let declared = read_u32(file, 10 + MASTER_KEY_LEN)?;
    if declared > MAX_VAULT_BYTES {
        return Err(Error::PortableTooLarge {
            limit: MAX_VAULT_BYTES,
            actual: declared,
        });
    }
    if file.len() != PLAIN_HEADER_LEN + declared {
        return Err(Error::PortableLengthMismatch);
    }
    Ok(PortableFile::PlainVault {
        master_key,
        vault: file[PLAIN_HEADER_LEN..].to_vec(),
    })
}

/// Parses the passphrase-protected container.
fn parse_encrypted(file: &[u8]) -> Result<PortableFile> {
    if file.len() < ENCRYPTED_HEADER_LEN {
        return Err(Error::PortableTruncated);
    }
    check_version(file[8])?;
    let recovery_len = read_u32(file, 9)?;
    let vault_len = read_u32(file, 13)?;
    if recovery_len == 0 || recovery_len > MAX_RECOVERY_BYTES {
        return Err(Error::PortableTooLarge {
            limit: MAX_RECOVERY_BYTES,
            actual: recovery_len,
        });
    }
    if vault_len == 0 || vault_len > MAX_VAULT_BYTES {
        return Err(Error::PortableTooLarge {
            limit: MAX_VAULT_BYTES,
            actual: vault_len,
        });
    }
    if file.len() != ENCRYPTED_HEADER_LEN + recovery_len + vault_len {
        return Err(Error::PortableLengthMismatch);
    }
    let vault_at = ENCRYPTED_HEADER_LEN + recovery_len;
    Ok(PortableFile::EncryptedVault {
        recovery: file[ENCRYPTED_HEADER_LEN..vault_at].to_vec(),
        vault: file[vault_at..].to_vec(),
    })
}

/// Packs the master key and the vault ciphertext into the plain container.
///
/// # Errors
///
/// [`Error::ExportTooLarge`] when the vault does not fit [`MAX_VAULT_BYTES`].
pub fn pack_plain(master: &MasterKey, vault: &[u8]) -> Result<Vec<u8>> {
    if vault.len() > MAX_VAULT_BYTES {
        return Err(Error::ExportTooLarge);
    }
    let bytes = master_key_to_bytes(master);
    #[expect(
        clippy::cast_possible_truncation,
        reason = "vault.len() was just compared against MAX_VAULT_BYTES, far below u32::MAX"
    )]
    let len = vault.len() as u32;

    let mut out = Vec::with_capacity(PLAIN_HEADER_LEN + vault.len());
    out.extend_from_slice(PLAIN_MAGIC);
    out.push(VERSION);
    out.push(0);
    out.extend_from_slice(bytes.expose_secret());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(vault);
    Ok(out)
}

/// Packs a recovery file and the vault ciphertext into the passphrase-protected container.
///
/// # Errors
///
/// [`Error::ExportTooLarge`] when either payload does not fit its limit. An empty recovery file
/// is refused by the same check: it cannot be the core recovery format.
pub fn pack_encrypted(recovery: &[u8], vault: &[u8]) -> Result<Vec<u8>> {
    if recovery.is_empty() || recovery.len() > MAX_RECOVERY_BYTES {
        return Err(Error::ExportTooLarge);
    }
    if vault.is_empty() || vault.len() > MAX_VAULT_BYTES {
        return Err(Error::ExportTooLarge);
    }
    #[expect(
        clippy::cast_possible_truncation,
        reason = "both lengths were just compared against limits far below u32::MAX"
    )]
    let recovery_len = recovery.len() as u32;
    #[expect(
        clippy::cast_possible_truncation,
        reason = "both lengths were just compared against limits far below u32::MAX"
    )]
    let vault_len = vault.len() as u32;

    let mut out = Vec::with_capacity(ENCRYPTED_HEADER_LEN + recovery.len() + vault.len());
    out.extend_from_slice(ENCRYPTED_MAGIC);
    out.push(VERSION);
    out.extend_from_slice(&recovery_len.to_be_bytes());
    out.extend_from_slice(&vault_len.to_be_bytes());
    out.extend_from_slice(recovery);
    out.extend_from_slice(vault);
    Ok(out)
}

/// Refuses a container version this build does not write.
fn check_version(version: u8) -> Result<()> {
    if version == VERSION {
        Ok(())
    } else {
        Err(Error::PortableUnsupportedVersion { version })
    }
}

/// Reads a big-endian `u32` at `at`, or reports a truncated file.
fn read_u32(file: &[u8], at: usize) -> Result<usize> {
    let end = at.checked_add(4).ok_or(Error::PortableTruncated)?;
    let bytes: [u8; 4] = file
        .get(at..end)
        .ok_or(Error::PortableTruncated)?
        .try_into()
        .map_err(|_| Error::PortableTruncated)?;
    Ok(u32::from_be_bytes(bytes) as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn master() -> MasterKey {
        MasterKey::generate().expect("OS randomness available")
    }

    fn vault_bytes() -> Vec<u8> {
        b"Q2FAVLT\0payload".to_vec()
    }

    #[test]
    fn the_magics_are_distinct_and_recognized() {
        assert_eq!(PLAIN_MAGIC, b"Q2FAKEY1");
        assert_eq!(ENCRYPTED_MAGIC, b"Q2FABK01");
        assert_eq!(KEY_ONLY_MAGIC, b"Q2FAREC\0");
        assert_ne!(PLAIN_MAGIC, ENCRYPTED_MAGIC);

        assert_eq!(detect(PLAIN_MAGIC), Some(PortableKind::PlainVault));
        assert_eq!(detect(ENCRYPTED_MAGIC), Some(PortableKind::EncryptedVault));
        assert_eq!(detect(KEY_ONLY_MAGIC), Some(PortableKind::KeyOnly));
        assert_eq!(detect(VAULT_MAGIC), None);
        assert_eq!(detect(b"nothing"), None);
        assert!(PortableKind::EncryptedVault.needs_password());
        assert!(!PortableKind::PlainVault.needs_password());
        assert!(!PortableKind::KeyOnly.needs_password());
    }

    #[test]
    fn a_plain_container_round_trips_its_two_parts() {
        let key = master();
        let expected = master_key_to_bytes(&key).expose_secret().to_vec();
        let packed = pack_plain(&key, &vault_bytes()).expect("it packs");
        assert_eq!(&packed[..8], PLAIN_MAGIC);
        assert_eq!(packed[8], VERSION);
        assert_eq!(packed[9], 0);

        let parsed = parse(&packed).expect("it parses");
        assert_eq!(parsed.kind(), PortableKind::PlainVault);
        match parsed {
            PortableFile::PlainVault { master_key, vault } => {
                assert_eq!(master_key.expose_secret(), &expected);
                assert_eq!(vault, vault_bytes());
            }
            other => panic!("expected a plain vault, actual {other:?}"),
        }
    }

    #[test]
    fn an_encrypted_container_round_trips_its_two_parts() {
        let recovery = vec![0x5A; 110];
        let packed = pack_encrypted(&recovery, &vault_bytes()).expect("it packs");
        assert_eq!(&packed[..8], ENCRYPTED_MAGIC);
        assert_eq!(packed[8], VERSION);
        match parse(&packed).expect("it parses") {
            PortableFile::EncryptedVault {
                recovery: got,
                vault,
            } => {
                assert_eq!(got, recovery);
                assert_eq!(vault, vault_bytes());
            }
            other => panic!("expected an encrypted vault, actual {other:?}"),
        }
    }

    #[test]
    fn a_truncated_container_is_refused() {
        let key = master();
        let packed = pack_plain(&key, &vault_bytes()).expect("it packs");
        for cut in [0, 1, 8, 9, 10, PLAIN_HEADER_LEN - 1] {
            let short = &packed[..cut.min(packed.len())];
            assert!(
                matches!(
                    parse(short),
                    Err(Error::PortableTruncated | Error::PortableBadMagic)
                ),
                "a container cut to {cut} bytes was accepted"
            );
        }
        let encrypted = pack_encrypted(&[0x11; 110], &vault_bytes()).expect("it packs");
        assert!(matches!(
            parse(&encrypted[..ENCRYPTED_HEADER_LEN - 1]),
            Err(Error::PortableTruncated)
        ));
    }

    #[test]
    fn a_length_beyond_the_limit_is_refused_before_it_is_used() {
        let key = master();
        let mut packed = pack_plain(&key, &vault_bytes()).expect("it packs");
        // Declare a payload of 4 GiB minus one in a 100-byte file.
        packed[PLAIN_HEADER_LEN - 4..PLAIN_HEADER_LEN].copy_from_slice(&[0xFF; 4]);
        assert!(matches!(
            parse(&packed),
            Err(Error::PortableTooLarge { .. })
        ));
    }

    #[test]
    fn trailing_bytes_are_refused_instead_of_ignored() {
        let key = master();
        let mut packed = pack_plain(&key, &vault_bytes()).expect("it packs");
        packed.push(0x00);
        assert!(matches!(parse(&packed), Err(Error::PortableLengthMismatch)));

        let mut encrypted = pack_encrypted(&[0x11; 110], &vault_bytes()).expect("it packs");
        encrypted.push(0x00);
        assert!(matches!(
            parse(&encrypted),
            Err(Error::PortableLengthMismatch)
        ));
    }

    #[test]
    fn a_version_this_build_does_not_read_is_refused() {
        let key = master();
        let mut packed = pack_plain(&key, &vault_bytes()).expect("it packs");
        packed[8] = 2;
        assert!(matches!(
            parse(&packed),
            Err(Error::PortableUnsupportedVersion { version: 2 })
        ));
    }

    #[test]
    fn a_bare_vault_file_is_refused_with_its_own_diagnosis() {
        let err = parse(b"Q2FAVLT\0anything");
        assert!(
            matches!(err, Err(Error::PortableVaultFileWithoutKey)),
            "actual {err:?}"
        );
        assert!(!is_portable(b"Q2FAVLT\0anything"));
    }

    #[test]
    fn the_reserved_byte_must_be_zero() {
        let key = master();
        let mut packed = pack_plain(&key, &vault_bytes()).expect("it packs");
        packed[9] = 1;
        assert!(matches!(parse(&packed), Err(Error::PortableBadMagic)));
    }
}
