<div align="center" style="align-items: center">

# Qualia2FA-Core

[简体中文](https://github.com/Qualia2FA/Qualia2FA-Core/blob/master/README.md) | English

The core library of Qualia2FA.

It carries all of Qualia2FA's core logic: code computation, URI parsing, the encrypted vault,
and device pairing and sync merging.

[![License](https://img.shields.io/github/license/Qualia2FA/Qualia2FA-Core?label=License)][License]
[![Releases](https://img.shields.io/github/downloads/Qualia2FA/Qualia2FA-Core/total?logo=github&label=Downloads)][Releases]
[![crates.io](https://img.shields.io/crates/d/qualia2fa-core?logo=crates.io&label=crates.io+Downloads)][crates.io]

[License]: https://github.com/Qualia2FA/Qualia2FA-Core/blob/master/LICENSE

[Releases]: https://github.com/Qualia2FA/Qualia2FA-Core/releases

[crates.io]: https://crates.io/crates/qualia2fa-core

</div>

---

It **deliberately contains no user interface or command-line entry point**, and performs
no I/O and no clock reads — so that Windows, Android and other platforms can each reuse it
as an independent project.

## Status

| Item | Value |
|---|---|
| Crate name | `qualia2fa-core` |
| Version | `0.3.0` |
| Type | pure library crate |
| Edition | 2024 |
| MSRV | **1.89** |
| Development toolchain | `stable` (pinned by `rust-toolchain.toml`) |
| License | `LGPL-3.0-or-later` |

The following features are supported:

- **2FA code computation**:
  - HOTP (RFC 4226)
  - TOTP (RFC 6238)
  - mOTP
  - Yandex OTP
  - Steam Guard
- Base32 (RFC 4648, in both lenient and strict modes)
- URI parsing and serialization (`otpauth://` and Aegis's `motp:` form)
- The encrypted vault (local storage format)
- **A tree of groups (parent links, entries and child groups in one order)**
- **Importing from Aegis's JSON / HTML / TXT exports (encrypted exports included), icons included**
- Recovery keys and the `.q2fa` containers (plain and encrypted vault)
- Challenge-response authentication
- Device pairing
- Sync payloads and merging
- The transport-layer protocol

## Usage

```toml
[dependencies]
qualia2fa-core = "0.2"
```

Computing a code:

```rust
use qualia2fa_core::otp::{self, Algorithm, Digits, OtpSecret};

let secret = OtpSecret::from_base32("JBSWY3DPEHPK3PXP")?;
// The current time is passed in by the caller — this library does not read the clock
let code = otp::totp_code(&secret, 1_700_000_000, 30, Algorithm::Sha1, Digits::SIX)?;
assert_eq!(code.len(), 6);
```

Importing an `otpauth://` URI:

```rust
use qualia2fa_core::uri;

let entry = uri::parse(
    "otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"
)?;
assert_eq!(entry.issuer.as_deref(), Some("GitHub"));
assert_eq!(entry.account, "alice");
```

Validating user input while tolerating clock drift:

```rust
use qualia2fa_core::otp;

// Returns the offset step that matched (0 = the current step, -1 = one step behind)
// rather than a boolean, so the entry's clock skew can be calibrated from it.
// The comparison is constant-time.
let offset = otp::verify_with_drift(&secret, counter, 1, algorithm, digits, &user_input);
```

### The encrypted vault

Once an `otpauth://` configuration is stored in the vault it becomes an **individually
encrypted** entry: each one has its own 128-bit random ID and XChaCha20-Poly1305
ciphertext, and apart from those IDs the file holds no plaintext semantics at all — not
even "TOTP or HOTP" is visible.

```rust
use qualia2fa_core::vault::{self, Entry, VaultFile};

// Build an entry from a scan result. The time is passed in by the caller
// (this library does not read the clock).
let parsed = qualia2fa_core::uri::parse("otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub")?;
let entry = vault::entry_from_parsed_uri(&parsed, now)?;

let mut file = VaultFile::create()?;              // generate a fresh random master key
let id = file.vault_mut().insert(entry)?;

let bytes = file.serialize()?;
vault::write_file_atomically(std::path::Path::new("vault.q2fa"), &bytes)?;
```

Reading it back requires the **master key** — the file does not contain it, only a value
derived from it (a 32-byte check value since format version 2, which answers "is this the
key you guessed" and cannot be inverted to the master key):

```rust
use qualia2fa_core::vault::{self, MasterKey};

let master: MasterKey = load_from_platform_keystore()?;   // e.g. the Windows TPM
let file = vault::read_file(master, std::path::Path::new("vault.q2fa"))?;
for (id, entry) in file.vault().iter() {
    println!("{id} {}", entry.name);
}
```

A few things worth knowing:

- **Losing the master key means the data can never be decrypted.** There is no server and
  no account password, so there is no recovery route either. Storing the master key in the
  platform hardware key store (Windows TPM, Android Keystore) is available, but that belongs
  to the upper layer (`qualia-dik` and the application); this library only generates, derives
  and holds it. The Secure Enclave on iOS and macOS is still planned.
- **The file can be rewritten freely by an attacker.** Flipping any single byte makes
  decryption fail, rather than quietly yielding tampered data. Your own storage layer
  should behave the same way.
- **Write to disk with `write_file_atomically`.** A plain `fs::write` can leave a truncated
  file after a power loss, and that means every entry is damaged.
- **Deletion leaves a tombstone** (encrypted the same way, holding only the ID and a
  timestamp), so that "another device still has this entry" can be adjudicated. Tombstones
  never expire and are 45 bytes each.
- The ciphertext length leaks the **length** of a note or an account name. This is a known,
  deliberate trade-off: hiding it would take padding to fixed-size blocks at several times
  the file size.

## Compatibility

**Vault format version: 4.** This version always writes version 4, and still reads version 1
through 3 (the readable set only grows). A version 4 group record is a name plus an ordered list
of child nodes, and an entry may carry an icon; the flat groups of versions 1-3 are read as named
groups under the top group. An older application reading a version 4 file gets a clear
"unsupported version" error; **the one exception** is the version 1 parser, which reports
trailing bytes (the 32-byte master key check value looks like extra content to it).

**Sync payload version: 4.** A payload only accepts the current version, so **syncing 0.2.x with
0.3.0 fails**, with a version error rather than an authentication failure (the version sits in the
cleartext header, so it is readable without the key). Both devices have to be upgraded together,
which is deliberate: the entry plaintext grew an icon node, the group plaintext changed shape, and
the length prefix is now u32.

Importing an Aegis export:

```rust
use qualia2fa_core::import::{self, ImportFormat};

// Bytes in, a report out: this library does no I/O and reads no clock
let report = import::import(&bytes, ImportFormat::Json, now, None)?;
for entry in &report.entries {
    println!("{}", entry.entry.name);
}
// Compared against the vault: what is new, what is already there, what needs a human
let matches = import::apply::compare(&report, &vault);
```

Exporting to one of six forms - the two `.q2fa` containers (`Vault` / `EncryptedVault`) and the four external ones (`Text` / `Json` / `EncryptedJson` / `Html`):

```rust
use qualia2fa_core::export::{self, ExportFormat};

// Bytes out of bytes in, again: this library does no I/O, and where the file goes is the
// caller's decision. Only EncryptedJson and EncryptedVault take a password; Vault holds the
// master key in clear, and the other plaintext forms are as sensitive as the vault itself.
// and as sensitive as the vault itself.
let bytes = export::export(vault, ExportFormat::EncryptedJson, Some(b"password"))?;
```

## Design conventions

### No I/O, no clock

It does not access the file system, the network or environment variables, and it does not
read the system clock. **Time is always passed in by the caller as `u64` Unix seconds.**
This is not fastidiousness: only with time as a parameter can the RFC 6238 test vectors be
verified deterministically.

Randomness comes only from `getrandom` (the OS CSPRNG), never through a user-space PRNG.

### Never panic

Every public function returns a `Result` with typed errors. No input may cause a panic —
including malicious QR codes, clipboard contents and hand-typed links. Error types **never
carry secret material**: not the raw input, not key bytes, not OTP codes.

### Handling of secret material

Every secret inside the library (OTP seeds, the vault master key, session keys) is carried
in a [`secrecy`] type, **never a bare `Vec<u8>` / `String`**, so that "this is a secret"
is visible in the type:

| Purpose | Type |
|---|---|
| Arbitrary byte secrets (seeds, keys, nonces) | `SecretBytes` (= `SecretSlice<u8>`) |
| Text secrets (passphrases, recovery phrases) | `SecretString` |
| Fixed-size / other secrets | `SecretBox` |
| Taking the plaintext | `ExposeSecret` / `ExposeSecretMut` |

All of the types above are re-exported by this library, so callers **do not** need to
depend on `secrecy` directly.

**That dependency has been audited manually** (whether a dependency is necessary cannot be
delegated to `cargo-deny`, so every item was checked):

- Its only required dependency is `zeroize ^1.6`, and the whole tree has exactly one
  `zeroize`.
- The optional `serde ^1` dependency is not enabled here and stays out of the dependency
  tree.
- The upstream monorepo is active (not archived, recently pushed to); the crate itself has
  had no release since 2024-10, making it **mature and stable rather than abandoned**, and
  it is a pure logic wrapper (no `unsafe`, no FFI).
- This library **touches it in exactly one place, `src/secret.rs`**, so the cost of
  swapping it out is contained.

**Upstream behaviour that is not what you would expect**:

- `secrecy`'s `Debug` **does not even print the length**; the output looks like
  `SecretBox<str>([REDACTED])`. Call `expose_secret()` yourself when you need the length.
- `secrecy` implements `CloneableSecret` only for **primitive integers**; there is **no**
  implementation for `Vec`/`String`/`Box`. This library therefore uses the cloneable
  `SecretSlice<u8>` for byte secrets throughout; **do not** change it to
  `SecretBox<Vec<u8>>`, which will not compile because it is not cloneable.
- These guarantees **only cover** "the plaintext was printed / erasure was forgotten / it
  was cloned by mistake". They do **not cover** the compiler copying plaintext into
  registers, stack copies or swap space. Under `forbid(unsafe_code)` there is no way to
  use `mlock` to prevent paging, and it does **not defend against malicious code in the
  same process** either.

### Platform-native calls do not belong in this library

Platform code that needs `unsafe` (such as the Windows TPM/CNG key store) is isolated in a
separate crate, to preserve this library's `#![forbid(unsafe_code)]`.

[`secrecy`]: https://crates.io/crates/secrecy

## Integrating into your own project

This library is published on crates.io: write the version number in `Cargo.toml` — no
submodule and no path dependency pointing at an upstream directory is needed.

```toml
[dependencies]
qualia2fa-core = "0.2"
```

> ⚠️ If you use **Gobley + uniffi** for Kotlin bindings, note that Gobley currently
> requires `uniffi = "0.29.4"`. **Do not add uniffi to this library** — bindings belong on
> the host side or in a separate FFI crate (such as
> [`Qualia2FA-FFI`](https://github.com/Qualia2FA/Qualia2FA-FFI)), so that this library's
> dependency surface stays clean and is not dragged around by the binding generator's
> version pin.

## Contributing

Please make sure everything is green before committing:

```powershell
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
cargo doc --no-deps            # documentation links and intra-doc links must not warn
```

Dependency audit and license policy (must be run after changing dependencies):

```powershell
cargo deny check
cargo audit
```

Fuzzing (needs nightly and cargo-fuzz, because `-Zsanitizer` is used):

```powershell
rustup toolchain install nightly --component rust-src
cargo install cargo-fuzz --locked

cd fuzz
cargo +nightly fuzz list
cargo +nightly fuzz run uri_parse -- -max_total_time=300
cargo +nightly fuzz run vault_parse -- -max_total_time=300
```

The `otpauth://` parser, Base32 decoding and vault file parsing are all
**attacker-controlled** input surfaces, so fuzz them whenever you change them. Historical
crash samples are frozen in `fuzz/regressions/` and CI runs them every round. See
[`fuzz/README.md`](https://github.com/Qualia2FA/Qualia2FA-Core/blob/master/fuzz/README.md) for details.

### MSRV policy

`rust-version = "1.89"` is a **minimum supported version declaration**, not the development
toolchain version:

- The **development toolchain** is pinned to `stable` by `rust-toolchain.toml`, so it does
  not drift from machine to machine.
- The **MSRV floor** is determined by the dependency stack (the current constraint comes
  from the crypto dependency stack; a future KEM would tighten it).
- CI has a separate MSRV job that compiles once with 1.89 on a real machine — **the
  declared MSRV must actually compile**, otherwise the field is a lie.

### Security discipline

- **Constant-time behaviour is a property of the compiled artifact, not of the crate.** A
  source file that looks constant-time may still compile into a branch (several RustSec
  advisories of this kind are codegen failures). Therefore **rerun the constant-time tests
  after upgrading any crypto dependency**.
- **Dependency auditing is a security control, not a chore.** The RustSec database added
  334 advisories in 2026 (172 in 2025), and nearly every upstream issue this project cares
  about was fixed in a patch or minor release. `Cargo.lock` is committed and CI runs
  `cargo-deny`.
- **Ship release builds only**: constant-time comparison libraries use `debug_assert` with
  branches that depend on secrets.
- **Secret material never enters** logs, error messages, panic messages or `Debug` output.
- `deny.toml` carries an explicit list of banned crates, each with its reason.

## License

This project is licensed under the **GNU Lesser General Public License v3.0 or later**
(`LGPL-3.0-or-later`). You may redistribute and/or modify this work under the terms of the
GNU Lesser General Public License as published by the Free Software Foundation, either
version 3 of the License, or (at your option) any later version.

- [`COPYING.LESSER`](https://github.com/Qualia2FA/Qualia2FA-Core/blob/master/COPYING.LESSER): the full text of LGPL-3.0
- [`LICENSE`](https://github.com/Qualia2FA/Qualia2FA-Core/blob/master/LICENSE): the full text of GPL-3.0 (LGPL-3.0 is incorporated by reference)

This work is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; even
without the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See
the license text for details.
