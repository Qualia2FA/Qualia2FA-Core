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

//! The two state files of the application lock: `lock.marker` and `lock.pending`.
//!
//! # What they are for
//!
//! A device that has never enabled the lock (a 0.3.0 installation, or a fresh
//! install) must be told apart from a device whose lock materials are gone. Those two
//! states look identical if only the presence of `master.key.pw` / `master.key.bio` is
//! checked, and confusing them would either bypass the lock or invite the user to
//! create a vault over data that is still there.
//!
//! - **`lock.marker`**: the lock is enabled. It records the format version, which of
//!   the two wraps were written, and when the migration completed.
//! - **`lock.pending`**: a creation, migration or recovery is in progress. Its presence
//!   means the next start must finish or roll back, never treat the device as a legacy
//!   installation.
//!
//! Neither file is secret and neither is an authentication factor. On its own a marker
//! proves nothing; what opens the vault is a wrap that decrypts to the right master key.
//!
//! # Why a binary format
//!
//! The files sit next to the vault and are read by one program. A fixed length makes a
//! truncated or appended file a single rejection instead of a partially understood
//! state, and a magic makes "this is some other application's file" say so.
//!
//! # Fail-closed rule
//!
//! A marker whose flags say "the lock is enabled" but which cannot be parsed is **not**
//! a legacy installation. The caller must report an unreadable lock and offer restore
//! or reset; it must never fall back to "no lock, open the vault without a password".

use crate::{Error, Result};

/// Magic of `lock.marker`.
const MARKER_MAGIC: &[u8; 8] = b"Q2FAMRK1";

/// Magic of `lock.pending`.
const PENDING_MAGIC: &[u8; 8] = b"Q2FAPND1";

/// Current version of both state files.
pub const STATE_FORMAT_VERSION: u8 = 1;

/// Total length of `lock.marker`.
pub const MARKER_LEN: usize = 19;

/// Total length of `lock.pending`.
pub const PENDING_LEN: usize = 18;

/// Flag bit: a password wrap was written.
const FLAG_PASSWORD: u8 = 0x01;

/// Flag bit: a platform-authentication wrap was written.
const FLAG_BIOMETRIC: u8 = 0x02;

/// Flags this build understands.
const KNOWN_FLAGS: u8 = FLAG_PASSWORD | FLAG_BIOMETRIC;

/// Offsets inside `lock.marker`.
mod marker_offset {
    /// Start of the magic.
    pub const MAGIC: usize = 0;
    /// Format version.
    pub const VERSION: usize = 8;
    /// Flag byte.
    pub const FLAGS: usize = 9;
    /// Reserved byte, must be 0.
    pub const RESERVED: usize = 10;
    /// Migration time (big-endian u64).
    pub const MIGRATED_AT: usize = 11;
}

/// Offsets inside `lock.pending`.
mod pending_offset {
    /// Start of the magic.
    pub const MAGIC: usize = 0;
    /// Format version.
    pub const VERSION: usize = 8;
    /// Reserved byte, must be 0.
    pub const RESERVED: usize = 9;
    /// Start time (big-endian u64).
    pub const STARTED_AT: usize = 10;
}

/// The `lock.marker` contents: the lock is enabled.
///
/// The two flags record which wraps were written **when the marker was written**. They
/// are advisory: a wrap can be deleted afterwards, and the caller must still look at the
/// files themselves before deciding what is available. The flags let the application
/// tell "there was only a password wrap" from "there were two and the biometric one is
/// gone", which is the difference between an expected state and a damaged one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockMarker {
    /// Whether `master.key.pw` was written.
    password: bool,
    /// Whether `master.key.bio` was written.
    biometric: bool,
    /// When the migration completed, Unix seconds.
    migrated_at: u64,
}

impl LockMarker {
    /// Builds a marker.
    ///
    /// # Errors
    ///
    /// - neither wrap present: [`Error::LockFileMalformed`] — a lock with no way in is
    ///   not a state a marker may describe;
    /// - `migrated_at` of zero: [`Error::TimestampZero`].
    pub fn new(password: bool, biometric: bool, migrated_at: u64) -> Result<Self> {
        if !password && !biometric {
            return Err(Error::LockFileMalformed {
                reason: "a lock marker must name at least one wrap",
            });
        }
        if migrated_at == 0 {
            return Err(Error::TimestampZero);
        }
        Ok(Self {
            password,
            biometric,
            migrated_at,
        })
    }

    /// Parses `lock.marker` bytes.
    ///
    /// # Errors
    ///
    /// - wrong length, magic or reserved byte: [`Error::LockFileMalformed`]
    /// - unknown version: [`Error::UnsupportedFormatVersion`]
    /// - unknown flag bits: [`Error::LockFileMalformed`]
    /// - neither wrap present or a zero timestamp: [`Error::LockFileMalformed`] /
    ///   [`Error::TimestampZero`]
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != MARKER_LEN {
            return Err(Error::LockFileMalformed {
                reason: "the lock marker does not have the fixed length",
            });
        }
        if &bytes[marker_offset::MAGIC..marker_offset::VERSION] != MARKER_MAGIC {
            return Err(Error::LockFileMalformed {
                reason: "magic mismatch: this is not a lock marker",
            });
        }
        if bytes[marker_offset::VERSION] != STATE_FORMAT_VERSION {
            return Err(Error::UnsupportedFormatVersion {
                version: bytes[marker_offset::VERSION],
            });
        }
        let flags = bytes[marker_offset::FLAGS];
        if flags & !KNOWN_FLAGS != 0 {
            return Err(Error::LockFileMalformed {
                reason: "the lock marker carries flag bits this build does not understand",
            });
        }
        if bytes[marker_offset::RESERVED] != 0 {
            return Err(Error::LockFileMalformed {
                reason: "the lock marker reserved byte must be 0",
            });
        }
        let migrated_at = u64::from_be_bytes(
            bytes[marker_offset::MIGRATED_AT..MARKER_LEN]
                .try_into()
                .map_err(|_| Error::LockFileMalformed {
                    reason: "failed to read the migration time",
                })?,
        );
        Self::new(
            flags & FLAG_PASSWORD != 0,
            flags & FLAG_BIOMETRIC != 0,
            migrated_at,
        )
    }

    /// Serializes the marker.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(MARKER_LEN);
        bytes.extend_from_slice(MARKER_MAGIC);
        bytes.push(STATE_FORMAT_VERSION);
        let mut flags = 0_u8;
        if self.password {
            flags |= FLAG_PASSWORD;
        }
        if self.biometric {
            flags |= FLAG_BIOMETRIC;
        }
        bytes.push(flags);
        bytes.push(0);
        bytes.extend_from_slice(&self.migrated_at.to_be_bytes());
        debug_assert_eq!(bytes.len(), MARKER_LEN);
        bytes
    }

    /// Whether a password wrap was recorded.
    #[must_use]
    pub const fn has_password(&self) -> bool {
        self.password
    }

    /// Whether a platform-authentication wrap was recorded.
    #[must_use]
    pub const fn has_biometric(&self) -> bool {
        self.biometric
    }

    /// When the migration completed, Unix seconds.
    #[must_use]
    pub const fn migrated_at(&self) -> u64 {
        self.migrated_at
    }
}

/// The `lock.pending` contents: a lock operation is in progress.
///
/// The file records only when the operation started. What it means is procedural: the
/// next start must finish the migration or roll it back before opening the vault; it is
/// never an authentication factor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockPending {
    /// When the operation started, Unix seconds.
    started_at: u64,
}

impl LockPending {
    /// Builds a pending marker.
    ///
    /// # Errors
    ///
    /// [`Error::TimestampZero`] when the time is zero.
    pub fn new(started_at: u64) -> Result<Self> {
        if started_at == 0 {
            return Err(Error::TimestampZero);
        }
        Ok(Self { started_at })
    }

    /// Parses `lock.pending` bytes.
    ///
    /// # Errors
    ///
    /// - wrong length, magic or reserved byte: [`Error::LockFileMalformed`]
    /// - unknown version: [`Error::UnsupportedFormatVersion`]
    /// - zero timestamp: [`Error::TimestampZero`]
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != PENDING_LEN {
            return Err(Error::LockFileMalformed {
                reason: "the pending marker does not have the fixed length",
            });
        }
        if &bytes[pending_offset::MAGIC..pending_offset::VERSION] != PENDING_MAGIC {
            return Err(Error::LockFileMalformed {
                reason: "magic mismatch: this is not a pending lock marker",
            });
        }
        if bytes[pending_offset::VERSION] != STATE_FORMAT_VERSION {
            return Err(Error::UnsupportedFormatVersion {
                version: bytes[pending_offset::VERSION],
            });
        }
        if bytes[pending_offset::RESERVED] != 0 {
            return Err(Error::LockFileMalformed {
                reason: "the pending marker reserved byte must be 0",
            });
        }
        let started_at = u64::from_be_bytes(
            bytes[pending_offset::STARTED_AT..PENDING_LEN]
                .try_into()
                .map_err(|_| Error::LockFileMalformed {
                    reason: "failed to read the start time",
                })?,
        );
        Self::new(started_at)
    }

    /// Serializes the pending marker.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(PENDING_LEN);
        bytes.extend_from_slice(PENDING_MAGIC);
        bytes.push(STATE_FORMAT_VERSION);
        bytes.push(0);
        bytes.extend_from_slice(&self.started_at.to_be_bytes());
        debug_assert_eq!(bytes.len(), PENDING_LEN);
        bytes
    }

    /// When the operation started, Unix seconds.
    #[must_use]
    pub const fn started_at(&self) -> u64 {
        self.started_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A marker with a fixed time.
    fn marker(password: bool, biometric: bool) -> LockMarker {
        LockMarker::new(password, biometric, 1_700_000_000).expect("valid marker")
    }

    /// Every combination of flags round trips.
    #[test]
    fn marker_roundtrip() {
        for (password, biometric) in [(true, false), (false, true), (true, true)] {
            let marker = marker(password, biometric);
            let encoded = marker.encode();
            assert_eq!(encoded.len(), MARKER_LEN);
            let parsed = LockMarker::parse(&encoded).expect("valid marker");
            assert_eq!(parsed, marker);
            assert_eq!(parsed.has_password(), password);
            assert_eq!(parsed.has_biometric(), biometric);
            assert_eq!(parsed.migrated_at(), 1_700_000_000);
        }
    }

    /// A marker that names no wrap cannot be built.
    #[test]
    fn marker_without_a_wrap_is_rejected() {
        assert!(matches!(
            LockMarker::new(false, false, 1),
            Err(Error::LockFileMalformed { .. })
        ));
    }

    /// A zero time is rejected in both constructors.
    #[test]
    fn zero_time_is_rejected() {
        assert!(matches!(
            LockMarker::new(true, false, 0),
            Err(Error::TimestampZero)
        ));
        assert!(matches!(LockPending::new(0), Err(Error::TimestampZero)));
    }

    /// Unknown flag bits are rejected.
    #[test]
    fn marker_unknown_flags_are_rejected() {
        let mut encoded = marker(true, false).encode();
        encoded[marker_offset::FLAGS] = 0x80;
        assert!(matches!(
            LockMarker::parse(&encoded),
            Err(Error::LockFileMalformed { .. })
        ));
    }

    /// A nonzero reserved byte is rejected.
    #[test]
    fn marker_reserved_byte_must_be_zero() {
        let mut encoded = marker(true, false).encode();
        encoded[marker_offset::RESERVED] = 1;
        assert!(matches!(
            LockMarker::parse(&encoded),
            Err(Error::LockFileMalformed { .. })
        ));
    }

    /// The version is checked.
    #[test]
    fn marker_version_is_checked() {
        let mut encoded = marker(true, false).encode();
        encoded[marker_offset::VERSION] = 2;
        assert!(matches!(
            LockMarker::parse(&encoded),
            Err(Error::UnsupportedFormatVersion { version: 2 })
        ));
    }

    /// Truncation and trailing bytes are rejected.
    #[test]
    fn marker_exact_length_is_required() {
        let encoded = marker(true, false).encode();
        for cut in [0_usize, 1, MARKER_LEN - 1] {
            assert!(LockMarker::parse(&encoded[..cut]).is_err());
        }
        let mut longer = encoded;
        longer.push(0);
        assert!(LockMarker::parse(&longer).is_err());
    }

    /// The marker layout is a public contract.
    #[test]
    fn marker_layout_is_stable() {
        assert_eq!(MARKER_LEN, 19);
        assert_eq!(marker_offset::MAGIC, 0);
        assert_eq!(marker_offset::VERSION, 8);
        assert_eq!(marker_offset::FLAGS, 9);
        assert_eq!(marker_offset::RESERVED, 10);
        assert_eq!(marker_offset::MIGRATED_AT, 11);
    }

    /// The pending marker round trips.
    #[test]
    fn pending_roundtrip() {
        let pending = LockPending::new(1_700_000_000).expect("valid pending");
        let encoded = pending.encode();
        assert_eq!(encoded.len(), PENDING_LEN);
        let parsed = LockPending::parse(&encoded).expect("valid pending");
        assert_eq!(parsed, pending);
        assert_eq!(parsed.started_at(), 1_700_000_000);
    }

    /// The pending marker rejects a nonzero reserved byte and the wrong length.
    #[test]
    fn pending_structure_is_checked() {
        let mut encoded = LockPending::new(1).expect("valid pending").encode();
        encoded[pending_offset::RESERVED] = 1;
        assert!(matches!(
            LockPending::parse(&encoded),
            Err(Error::LockFileMalformed { .. })
        ));

        let encoded = LockPending::new(1).expect("valid pending").encode();
        assert!(LockPending::parse(&encoded[..PENDING_LEN - 1]).is_err());
        let mut longer = encoded;
        longer.push(0);
        assert!(LockPending::parse(&longer).is_err());
    }

    /// The pending layout is a public contract.
    #[test]
    fn pending_layout_is_stable() {
        assert_eq!(PENDING_LEN, 18);
        assert_eq!(pending_offset::MAGIC, 0);
        assert_eq!(pending_offset::VERSION, 8);
        assert_eq!(pending_offset::RESERVED, 9);
        assert_eq!(pending_offset::STARTED_AT, 10);
    }

    /// A marker and a pending file cannot be confused.
    #[test]
    fn the_two_files_have_different_magics() {
        let marker = marker(true, false).encode();
        let pending = LockPending::new(1).expect("valid pending").encode();
        assert!(LockMarker::parse(&pending).is_err());
        assert!(LockPending::parse(&marker).is_err());
    }
}
