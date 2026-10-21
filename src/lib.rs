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

//! The Qualia2FA core library.
//!
//! This crate carries the two-factor authentication (2FA) core logic of Qualia2FA and
//! deliberately contains no user interface or command-line entry point, so that front
//! ends such as a GUI, a CLI, or a mobile application can each depend on this library
//! as a separate crate.
//!
//! # Purity contract
//!
//! This library is a pure logic library with **no I/O and no clock**:
//!
//! - It does not access the file system, the network, or environment variables, and it
//!   does not read the system clock.
//! - The current time is passed in by the caller as `u64` Unix seconds.
//! - Randomness comes only from [`getrandom`], never through a user-space PRNG.
//! - [`#![forbid(unsafe_code)]`](self) — the whole crate contains no `unsafe`.
//!
//! # Status
//!
//! Implemented: Base32 (RFC 4648), HOTP (RFC 4226), TOTP (RFC 6238), Steam Guard, mOTP,
//! Yandex OTP, `otpauth://` parsing, the encrypted vault, recovery files, device pairing,
//! and the sync protocol.
//!
//! # Usage
//!
//! ```
//! // Version number.
//! assert_eq!(qualia2fa_core::VERSION, env!("CARGO_PKG_VERSION"));
//!
//! // Base32 decoding (RFC 4648); tolerates lowercase, missing padding, and whitespace.
//! use qualia2fa_core::{base32, ExposeSecret};
//! let seed = base32::decode("MZXW6YTBOI======").expect("valid Base32");
//! assert_eq!(seed.expose_secret(), b"foobar");
//! ```
//!
//! # License
//!
//! Licensed under the GNU Lesser General Public License v3.0 or later
//! (`LGPL-3.0-or-later`); see `COPYING.LESSER` and `LICENSE` in the repository root.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]

pub mod auth;
pub mod base32;
mod error;
pub mod export;
pub mod flow;
pub mod import;
pub mod lock;
pub mod motp;
pub mod otp;
pub mod pairing;
pub mod portable;
pub mod recovery;
mod secret;
pub mod sync;
pub mod transport;
pub mod uri;
pub mod vault;
pub mod yaotp;

pub use auth::{Responder, Verified, Verifier};
pub use error::{Error, Result};

/// Public types of the registration and login orchestration.
///
/// Only the **user journey** layer and the two injection points are exported. No
/// intermediate type split into steps is exported: a caller may legally drive
/// `vault`/`pairing`/`device` in order by itself, but doing so bypasses the ordering
/// this module guarantees (see the module documentation of [`flow`]), so the public
/// surface does not encourage it.
pub use flow::{DeviceKeys, Joiner, Login, Registered, SecureStore};

/// Public types of device identity.
///
/// Device identity lives in [`qualia_dik`] — an independent, reusable crate that any
/// project needing "a pair of P-256 identity keys in platform hardware" can use
/// without accepting this crate's vault format or sync protocol. They are re-exported
/// here so that downstream code does not have to depend on both crates.
///
/// `DevicePublicKey` and `DeviceSignature` are **not secret** — they are meant to be
/// printed on QR codes, written to logs, and propagated between devices — so they are
/// exported separately from the secret types, which makes it visible in an import
/// list which types may be printed freely.
pub use qualia_dik::{DeviceId, DevicePublicKey, DeviceSignature};

/// Public types of the pairing protocol.
///
/// Only "what each side needs" is exported: the QR payload, the sessions in both
/// directions, and the result. Internal session keys and confirmation-tag computation
/// are not exported — they are part of the protocol invariants and must not be
/// recombined by upper layers into other uses.
pub use pairing::{Adoption, JoinerSession, NonceLog, PendingSession, QrPayload};

/// Public types of the recovery key.
pub use recovery::{KdfParams, export as export_recovery, import as import_recovery};

/// Public types of the application lock's password wrap.
///
/// The wrap has its own file format and its own KDF domain; see [`lock`]. The
/// platform-authentication wrap is not here: it is a separate library, because the
/// key never leaves the platform and this crate touches no platform API.
pub use lock::{
    FILE_LEN as LOCK_WRAP_LEN, LockMarker, LockPending, WrapHeader, unwrap as unwrap_lock_password,
    wrap as wrap_lock_password,
};

/// Public types of the transport layer.
///
/// Only the **protocol** half: capability declaration, the channel contract, the
/// session, and its result type. Concrete channels (LAN, QR code, hotspot) implement
/// [`Transport`] on the device side — they all need I/O and platform APIs, and this
/// crate touches neither.
///
/// Deliberately does **not** export any intermediate type "split into steps": a caller
/// either uses [`SyncSession`] or assembles the parts in `sync` itself. The former
/// guarantees the ordering, the latter does not.
pub use transport::{
    Recipient, Roster, SharePlan, SyncOutcome, SyncSession, Transport, TransportCapabilities,
};

pub use secret::{
    ExposeSecret, ExposeSecretMut, SecretBox, SecretBytes, SecretSlice, SecretString,
};

/// Re-exports the OS CSPRNG so that upper layers (FFI / device side) use the **same**
/// randomness implementation.
///
/// This crate is the only place that declares a `getrandom` dependency, so upper layers
/// take randomness from here instead of declaring it again — separate declarations
/// would let the two version requirements drift apart and end up with two different
/// CSPRNG wrappers in one binary.
///
/// Upper layers call `qualia2fa_core::getrandom::fill(&mut buf)`.
///
/// Note: prefer the high-level APIs this library already provides when random bytes are
/// needed; calling this directly is the opening left for cases such as "generate a new
/// seed", where the upper layer must decide length and purpose itself.
pub use getrandom;

/// Version of this library, taken from `package.version` in `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_starts_with_a_digit() {
        assert!(
            VERSION.starts_with(char::is_numeric),
            "bad version: {VERSION}"
        );
    }

    #[test]
    fn version_has_three_semver_components() {
        assert_eq!(VERSION.split('.').count(), 3, "bad version: {VERSION}");
    }
}
