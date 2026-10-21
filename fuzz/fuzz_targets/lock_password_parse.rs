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

//! Fuzz target: the password-wrapped master key (`master.key.pw`).
//!
//! # Input surface
//!
//! The file sits beside the vault on a device an attacker may reach. It is also
//! copied by backup tools and restored by hand, so it can arrive truncated, with a
//! rewritten header, or entirely forged. Every field except the magic is
//! attacker-controlled once the attacker can write the file.
//!
//! # Properties covered
//!
//! 1. **Never panics** for any length or content.
//! 2. **Length and magic are checked before any allocation**.
//! 3. **The derivation parameters are bounded before Argon2id runs** — the file
//!    declares its own cost, so an unbounded `m_cost` turns opening a file into a
//!    memory-exhaustion attack.
//!
//! # Why the target does not simply call `unwrap` on everything
//!
//! `unwrap` runs Argon2id for every structurally valid file. A random 4-byte
//! `m_cost` is frequently below the 1 GiB limit yet still hundreds of MiB, which
//! would make fuzzing spend its whole budget in one derivation. The target
//! therefore asks the cheap header parser first and only reaches the KDF when the
//! file declares a cost small enough to finish inside a fuzz iteration. Both
//! paths — header rejection and authenticated decryption — are covered.

#![no_main]

use libfuzzer_sys::fuzz_target;
use qualia2fa_core::{SecretString, lock};

/// The password offered to every candidate file.
///
/// A fixed public value: this target is about parsing and bounds, not about password
/// strength, and a real user password must not appear in a fuzz corpus.
const PASSWORD: &str = "fuzz password, not a secret";

/// Memory cost above which the target does not run the KDF.
const MAX_FUZZ_MEMORY_KIB: u32 = 8 * 1024;

/// Iteration count above which the target does not run the KDF.
const MAX_FUZZ_ITERATIONS: u32 = 4;

fuzz_target!(|data: &[u8]| {
    let password = SecretString::from(PASSWORD);

    if let Ok(header) = lock::WrapHeader::parse(data) {
        let params = header.params();
        if params.memory_kib() <= MAX_FUZZ_MEMORY_KIB
            && params.iterations() <= MAX_FUZZ_ITERATIONS
        {
            let _ = lock::unwrap(data, &password);
        }
    }
});
