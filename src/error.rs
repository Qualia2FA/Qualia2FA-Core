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

//! Error types.
//!
//! Every public function of this library returns [`Result`], and **no input may cause a
//! panic**.
//!
//! # Secret-handling discipline
//!
//! Error values **never carry secret material**: no raw input, no key bytes, no OTP code. The
//! variants in this module record only which class of input was invalid plus the **non-secret**
//! numbers needed to locate the problem (lengths, positions), so a caller can diagnose it
//! without the value leaking.

use thiserror::Error;

/// The unified error type of this library.
///
/// The enum is `#[non_exhaustive]`, so a `match` outside this crate must have a wildcard arm,
/// and adding a variant is not a breaking change for downstream code. Variants are added as
/// the library grows.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// A failure reported by the device identity crate.
    ///
    /// # Why this wraps the foreign error instead of copying its variants
    ///
    /// Device identity (public key representation, fingerprints, signature verification and
    /// the platform key store) lives in [`qualia_dik`](https://docs.rs/qualia-dik), an
    /// independently reusable crate. This crate needs **the same** failure classification, not
    /// a look-alike one of its own.
    ///
    /// Copying the variants would let the two enums drift: the other crate gains a
    /// `HardwareUnavailable`, this one forgets it, and "no TPM" reaches Core callers through a
    /// silent `_ =>` wildcard arm. Wrapping makes the compiler point out every new variant that
    /// needs handling when the dependency is upgraded.
    ///
    /// The `source()` chain also shows that the failure came from the device identity crate,
    /// instead of flattening it into a local `reason` string.
    #[error(transparent)]
    Device(#[from] qualia_dik::Error),

    /// The Base32 input contains a character outside the alphabet.
    ///
    /// Only the **position** is reported, never the character at that position, so that input
    /// content (which may come from a key) does not reach the logs.
    #[error("Base32 input has an invalid character at position {index}")]
    Base32InvalidCharacter {
        /// Position of the invalid character in the character sequence **after ASCII whitespace
        /// has been removed**.
        ///
        /// It is not a raw byte offset because users often paste seeds from a web page with
        /// spaces or line breaks, and "which valid character" locates the problem more easily
        /// than "which byte".
        index: usize,
    },

    /// The Base32 input length (after padding is stripped) is not a valid remainder modulo 8.
    ///
    /// The only valid Base32 length remainders are 0, 2, 4, 5 and 7.
    #[error("invalid Base32 length: {length} significant characters")]
    Base32InvalidLength {
        /// Number of valid characters after padding is removed.
        length: usize,
    },

    /// Corrupt Base32 encoding: the unused bits of the last character are not zero.
    ///
    /// This is not a padding-format problem — padding itself may be absent or present (both are
    /// accepted). It means the encoded data itself is corrupt, for example significant bits
    /// written into padding bits that must be zero.
    #[error("Base32 encoding has non-zero residual bits at the end; the data is corrupt")]
    Base32InvalidPadding,

    /// The OTP secret is empty.
    ///
    /// Kept separate from [`Error::SecretTooShort`]: an empty seed is a **structural** problem
    /// (the URI has no `secret` at all, or Base32 decodes to nothing), while a short seed is a
    /// **strength** problem. The former must be rejected, the latter is a UI warning — merging
    /// them leaves the caller unable to tell the two apart.
    #[error("OTP secret is empty")]
    SecretEmpty,

    /// The OTP secret is shorter than the minimum required by the selected algorithm.
    ///
    /// **Note**: this library currently rejects only empty secrets and never returns this error
    /// for a short one. HMAC accepts keys of any length and short seeds exist in the real world;
    /// a short seed is a **warning** to be surfaced by the UI, see
    /// `otp::recommended_min_secret_len`.
    #[error("OTP secret is too short: at least {required} bytes required, {actual} bytes given")]
    SecretTooShort {
        /// Minimum seed length in bytes required by RFC 6238 for this algorithm.
        required: usize,
        /// Actual length in bytes. The length itself is not a secret.
        actual: usize,
    },

    /// The `algorithm` parameter of an `otpauth://` URI is not recognized.
    ///
    /// **Rejected rather than falling back to SHA-1**: a silent fallback gives the user a code
    /// that is consistently wrong, with nothing in the error to trace it back.
    #[error("unsupported algorithm: {name}")]
    UnsupportedAlgorithm {
        /// The raw parameter value, truncated to at most 16 characters.
        ///
        /// Truncation is required: the value comes from an attacker-controlled URI, and
        /// arbitrary-length input must not be carried into the logs verbatim.
        name: String,
    },

    /// The `digits` parameter of an `otpauth://` URI is outside the supported range.
    ///
    /// Reported when the value is not a plain decimal digit count in the first place
    /// (`""`, `"six"`, `"06"`, a number too large for a byte). A well-formed number that is
    /// merely out of range is reported by [`Error::DigitsZero`] or [`Error::DigitsTooMany`],
    /// which carry the reason.
    #[error("unsupported digit count: {value} (a plain decimal count from 1 to 9 is expected)")]
    UnsupportedDigits {
        /// The raw parameter value, truncated to at most 16 characters.
        value: String,
    },

    /// A code was requested with zero digits.
    ///
    /// A zero-width code is not a code: there would be nothing to display and nothing to
    /// compare, and `10^0 = 1` makes every code identical.
    #[error("a code must have at least one digit")]
    DigitsZero,

    /// A code was requested with ten or more digits.
    ///
    /// **The limit comes from the truncation, not from the integer width**: RFC 4226 §5.3
    /// extracts a 31-bit value from the HMAC, so at ten digits the reachable code space is
    /// only `2^31 / 10^10` (about 21%) of the range — codes above `2^31` can never appear,
    /// and the ones that can are not uniformly distributed. Widening the integer type does
    /// not help; supporting ten digits would need a different truncation, which no existing
    /// implementation would agree with.
    #[error(
        "a code cannot have {count} digits: RFC 4226 §5.3 truncates the HMAC to 31 bits, so ten or more digits would be biased (1 to 9 are accepted)"
    )]
    DigitsTooMany {
        /// The requested digit count.
        count: u8,
    },

    /// The TOTP `period` is 0, which would cause a division by zero.
    #[error("TOTP period must not be 0")]
    InvalidPeriod,

    /// A code was requested from an algorithm that mixes a user-entered PIN into the
    /// computation, but no PIN is set.
    ///
    /// mOTP and Yandex OTP both fold a PIN into the code. Without one the algorithm has **no
    /// defined output**: the reference implementation raises an error rather than substituting
    /// an empty string. This is deliberately an error and not a default — a code computed with
    /// an empty PIN looks perfectly plausible and no server will ever accept it, which is the
    /// hardest kind of failure for a user to diagnose.
    ///
    /// An **empty** PIN is a different thing and is accepted: it means the user's PIN *is* the
    /// empty string, which the algorithm handles like any other value.
    #[error("{otp_type} requires a PIN before a code can be generated")]
    PinRequired {
        /// Which algorithm needs it (`"mOTP"` or `"Yandex OTP"`).
        otp_type: &'static str,
    },

    /// A Yandex OTP secret is neither 16 nor 26 bytes long.
    ///
    /// The scheme has exactly two secret forms: 16 bytes (what a QR code carries) and 26 bytes
    /// (16 bytes plus a trailing checksum). Any other length is not a Yandex secret, so it is
    /// rejected instead of being truncated to something plausible.
    #[error("Yandex OTP secret must be 16 or 26 bytes, got {len}")]
    YandexSecretLength {
        /// Actual length in bytes. The length itself is not a secret.
        len: usize,
    },

    /// The trailing checksum of a 26-byte Yandex OTP secret does not match its contents.
    ///
    /// The checksum is a polynomial remainder over the secret (see `yaotp::normalize_secret`),
    /// and it is a **data-integrity** check, not a cryptographic one: it exists so that a
    /// mistyped or truncated secret is reported as damaged at import time instead of turning
    /// into codes that no server will ever accept. It carries no information about the secret
    /// itself.
    #[error("Yandex OTP secret checksum does not match its contents")]
    YandexSecretChecksum,

    /// Cryptographic random bytes cannot be obtained from the operating system.
    ///
    /// This is an **unrecoverable** failure: the library deliberately uses no user-space PRNG as
    /// a fallback, because a deterministic seed makes independently generated keys collide.
    /// Failing the operation and letting the user retry is preferable to silently switching to a
    /// weak random source.
    ///
    /// Triggered when the `getrandom` backend is unavailable on the target platform (a
    /// restricted sandbox, a missing syscall, or a kernel entropy source that failed to
    /// initialize).
    ///
    /// **It carries no `getrandom::Error` detail**: that type's internal representation differs
    /// across versions and platforms and offers the caller nothing actionable — retrying or
    /// telling the user is all that can be done.
    #[error("cannot obtain secure random bytes from the operating system")]
    RandomnessUnavailable,

    /// The URI scheme is not one this library understands.
    #[error("unsupported URI scheme (expected otpauth:// or motp:)")]
    UriUnsupportedScheme,

    /// The URI has no type component (no `/` after the scheme).
    #[error("URI is missing its type component (expected totp, hotp, motp, yaotp or steam)")]
    UriMissingType,

    /// The URI type is not one of the supported schemes.
    #[error("unsupported URI type: {name}")]
    UriUnsupportedType {
        /// The raw type component, truncated to at most 16 characters.
        name: String,
    },

    /// A parameter that has no meaning for this type is present.
    ///
    /// Rejected rather than ignored, for the reason [`Error::UriUnexpectedCounter`] gives: a
    /// parameter that is silently dropped is a configuration the user believes in and that the
    /// code does not implement.
    #[error("a {uri_type} URI cannot carry {parameter}")]
    UriParameterNotSupported {
        /// The parameter name, from this library's own list.
        parameter: &'static str,
        /// The URI type, from this library's own list.
        uri_type: &'static str,
    },

    /// A `yaotp` URI asked for an algorithm other than SHA-256.
    ///
    /// Yandex OTP truncates an **eight-byte** window of the digest, so a shorter digest (SHA-1
    /// has 20 bytes and the window starts as late as byte 15) would read past its end. The
    /// scheme is defined for SHA-256 only; honouring the parameter is impossible and ignoring
    /// it would compute codes that never match.
    #[error(
        "Yandex OTP is defined for SHA-256 only, but the URI asked for {algorithm}: the eight-byte truncation reads past the end of a shorter digest"
    )]
    YandexAlgorithmUnsupported {
        /// The algorithm name the URI carried.
        algorithm: &'static str,
    },

    /// A `steam` URI asked for an algorithm other than SHA-1.
    #[error("Steam Guard is defined for SHA-1 only, but the URI asked for {algorithm}")]
    SteamAlgorithmUnsupported {
        /// The algorithm name the URI carried.
        algorithm: &'static str,
    },

    /// A `steam` URI asked for a code length other than five.
    #[error("a Steam Guard code is always 5 characters, but the URI asked for {digits}")]
    SteamDigitsUnsupported {
        /// The digit count the URI carried.
        digits: u8,
    },

    /// A `pin` parameter is not usable.
    ///
    /// The pin travels Base32-encoded (so that any character a user may choose survives the
    /// query string), and the decoded bytes must be UTF-8.
    #[error("the pin parameter is invalid: {reason}")]
    UriInvalidPin {
        /// What was wrong, without echoing the pin itself.
        reason: &'static str,
    },

    /// The URI has no `secret` parameter.
    #[error("URI is missing the required secret parameter")]
    UriMissingSecret,

    /// The HOTP URI has no `counter` parameter.
    #[error("HOTP URI is missing the required counter parameter")]
    UriMissingCounter,

    /// A TOTP URI carries a `counter` parameter.
    ///
    /// Rejected rather than ignored: such a URI signals a faulty generator, and ignoring it
    /// hands the user an entry that looks normal but means something else.
    #[error("TOTP URI must not carry a counter parameter")]
    UriUnexpectedCounter,

    /// The URI contains a known parameter more than once.
    ///
    /// Implementations disagree on whether the first or the last occurrence wins: a classic
    /// parsing ambiguity, and an attack surface.
    #[error("URI contains a duplicate parameter: {name}")]
    UriDuplicateParameter {
        /// The duplicated parameter name (truncated to 16 characters).
        name: String,
    },

    /// A URI parameter value is invalid.
    #[error("invalid URI parameter {name}: {reason}")]
    UriInvalidParameter {
        /// Parameter name.
        name: String,
        /// Reason that does not include the full raw value (the value itself is truncated).
        reason: String,
    },

    /// The percent encoding in the URI is malformed.
    #[error("URI contains invalid percent encoding (% must be followed by two hexadecimal digits)")]
    UriInvalidPercentEncoding,

    /// The issuer in the label and the `issuer` parameter disagree.
    ///
    /// Rejected: two different issuers mean the URI was assembled or tampered with, and silently
    /// picking one would bind an entry's codes to the wrong service.
    #[error("issuer conflict: the label says {in_label}, the parameter says {in_parameter}")]
    UriIssuerMismatch {
        /// The issuer from the label prefix (truncated).
        in_label: String,
        /// The value from the `issuer` parameter (truncated).
        in_parameter: String,
    },

    /// The account name in the URI label contains `:`.
    ///
    /// The label uses `:` to separate issuer from account, so a `:` inside the account name
    /// cannot be told apart from the separator and creates round-trip ambiguity: after a
    /// serialize-then-parse cycle, the ownership of issuer and account changes **silently**.
    /// Percent encoding does not help — `%3A` and a literal `:` are indistinguishable once
    /// decoded.
    ///
    /// Both parsing and serialization therefore reject it, enforcing the invariant.
    #[error(
        "the account name must not contain a colon (it is confused with the issuer separator): {account}"
    )]
    UriAccountContainsColon {
        /// The account name, truncated to 32 characters.
        account: String,
    },

    /// The vault file is shorter than its declared structure, or the structure is cut off here.
    ///
    /// The most common structural problem: the file was truncated, or a length field claims more
    /// bytes than actually remain.
    #[error("vault file is incomplete or truncated")]
    VaultTruncated,

    /// The magic number at the start of the vault file does not match.
    ///
    /// It means this is not a vault file (the wrong file was picked, or the file was replaced
    /// with something else).
    #[error("not a Qualia2FA vault file")]
    VaultBadMagic,

    /// The vault file format version is not supported by this build.
    #[error("unsupported vault format version: {version}")]
    VaultUnsupportedVersion {
        /// Version declared in the file.
        version: u8,
    },

    /// The reserved byte in the vault file header is not 0.
    ///
    /// Reserved bytes exist precisely so that they may become non-zero later. The current
    /// version must reject a non-zero value: it means the file was written by a newer version
    /// that may have given the byte a meaning this version does not know, and reading on would
    /// parse it under wrong assumptions.
    #[error("vault reserved byte must be 0, but is {value}")]
    VaultReservedByteNotZero {
        /// Actual value in the file.
        value: u8,
    },

    /// The record kind byte in the vault file is not recognized.
    ///
    /// **Not treated as a live entry**: guessing that an unknown kind "is probably an entry"
    /// would let a tombstone written by a future version come back to life as an entry here.
    #[error("unrecognized vault record kind: {value}")]
    VaultUnknownRecordKind {
        /// Actual value in the file.
        value: u8,
    },

    /// A single record exceeds the length limit.
    ///
    /// The limit exists to reject a malicious file claiming to hold 4 GiB and to avoid allocating
    /// huge buffers for untrusted input. This is therefore a **structural** problem, not the
    /// business problem of "an entry that is too large".
    #[error("vault record is too long: limit {limit} bytes, {actual} bytes declared")]
    VaultRecordTooLong {
        /// Allowed limit.
        limit: usize,
        /// Length declared in the file.
        actual: usize,
    },

    /// The vault holds more records than the limit allows.
    #[error(
        "vault record count exceeds the limit (at most {})",
        crate::vault::MAX_RECORDS
    )]
    VaultTooManyRecords,

    /// The vault file has extra bytes at the end.
    ///
    /// **Rejected rather than ignored**: extra bytes mean content was appended and this version
    /// cannot explain what it is. Ignoring them would make the fact that the file was modified
    /// disappear.
    #[error("vault file has {count} extra bytes at the end")]
    VaultTrailingBytes {
        /// Number of extra bytes.
        count: usize,
    },

    /// The same `entry_id` appears twice in the vault file.
    ///
    /// **Rejected rather than overwritten**: a duplicate ID means the file was crafted or
    /// corrupted. Silently keeping one of them makes the user lose a 2FA entry, showing up as
    /// "one code suddenly stopped working" — extremely hard to trace.
    #[error("vault file contains a duplicate entry ID")]
    VaultDuplicateEntryId,

    /// The master key check value in the file has the wrong structure (length mismatch).
    ///
    /// Strictly separated from [`Error::VaultDecryptionFailed`]: **this one is a structural
    /// problem, that one means a wrong key or a modified file**. Merging the two reports a
    /// crafted file as "your key is wrong", sending the user to compare keys when the problem is
    /// somewhere else entirely.
    ///
    /// The check value is a fixed-length plaintext field, so a length mismatch means the file was
    /// truncated, appended to, or never written in the format at all — all three mean "this file
    /// is untrustworthy", not "wrong key".
    #[error("vault file has a master key check value of the wrong length")]
    VaultBadKeyCheck,

    /// No entry with this identifier exists.
    ///
    /// Different from "the vault is empty": the caller named one specific entry and it is not
    /// there. The layer above must tell two UI actions apart — "the list is empty, invite the
    /// user to add an entry" versus "the entry you were working on is gone, refresh the list".
    /// Treating the latter as the former shows an empty list while the user was just looking at
    /// the entry.
    ///
    /// A common cause is synchronization having deleted the entry on the other device while this
    /// one still holds its identifier.
    #[error("no such entry in the vault")]
    VaultEntryNotFound,

    /// A vault file holds two group records with the same identifier.
    ///
    /// Refused rather than treated as an overwrite, for the same reason as
    /// [`Error::VaultDuplicateEntryId`]: one of the two orderings would be dropped silently, and
    /// an ordering that disappears takes the user's arrangement with it.
    #[error("the vault holds two groups with the same identifier")]
    VaultDuplicateGroupId,

    /// No group with that identifier exists.
    #[error("no such group in the vault")]
    VaultGroupNotFound,

    /// An ordering names an entry the vault does not hold.
    ///
    /// Rejected when **setting** an ordering: the caller passes identifiers, and one that names
    /// nothing means the caller is out of step with the vault. When **reading** a file, a
    /// reference to a missing entry is skipped instead - there the caller is a peer device and
    /// the entries may simply not have arrived yet.
    #[error("an ordering names an entry the vault does not hold")]
    VaultGroupUnknownEntry,

    /// The top group cannot be renamed, removed or reordered.
    ///
    /// It is the collection of the entries that belong to no named group: it is pinned at the
    /// top of the interface and has no name to edit, so every operation that would change what
    /// it *is* is refused rather than silently ignored. Its contents (the ordering) remain
    /// editable, which is the whole point of it being a group.
    #[error("the top group cannot be renamed, removed or reordered")]
    VaultTopGroupImmutable,

    /// One group holds more child references than the format can carry.
    ///
    /// The list travels in a single length-prefixed node, so it is bounded by
    /// [`Error::FieldTooLong`]'s limit divided by the size of one child reference.
    #[error("a group holds {actual} children, at most {limit} fit in the format")]
    VaultGroupTooManyChildren {
        /// The maximum the format allows.
        limit: usize,
        /// How many were supplied.
        actual: usize,
    },

    /// One child holds two positions in the same ordering.
    ///
    /// A list is a **sequence**: the same entry or group cannot come both before and after
    /// another one. Two different groups holding the same child is a different question, and
    /// the vault answers it by moving the child instead of refusing.
    #[error("a child appears twice in the same ordering")]
    VaultGroupDuplicateChild,

    /// Moving the children would put a group inside itself.
    ///
    /// The tree has no cycles by definition: "the parent of A is B" and "the parent of B is A"
    /// cannot both hold. Offering such a list is refused before anything is written, rather
    /// than left for a traversal to discover - a cycle makes every walk over the tree either
    /// loop forever or need a visited set, and the one place to prevent it is where the list
    /// is set.
    #[error("the children would put a group inside itself")]
    VaultGroupCycle,

    /// A group would be nested more deeply than the tree allows.
    ///
    /// The top group is depth zero. Past the limit the interface has no room to indent a group,
    /// so the nesting is refused when a list is written and repaired when a file is read.
    #[error("a group would be nested {actual} levels deep, at most {limit} are allowed")]
    VaultGroupDepthExceeded {
        /// The deepest nesting this library allows.
        limit: usize,
        /// How deep the operation would place the group.
        actual: usize,
    },

    /// The export is larger than this library reads.
    ///
    /// Compared **before** anything is allocated or parsed: the size comes from the file, and a
    /// small header claiming gigabytes must not turn into an allocation.
    #[error("the export is {actual} bytes; at most {limit} are read")]
    ImportFileTooLarge {
        /// The limit.
        limit: usize,
        /// The size of the input.
        actual: usize,
    },

    /// The export holds more entries than this library reads.
    #[error("the export holds {actual} entries; at most {limit} are read")]
    ImportTooManyEntries {
        /// The limit.
        limit: usize,
        /// How many the export holds.
        actual: usize,
    },

    /// The export nests more deeply than this library reads.
    ///
    /// Checked by scanning the bytes **before** they reach the JSON parser: that parser recurses,
    /// so a deeply nested document would exhaust the stack, and a stack overflow is not a
    /// catchable error - it takes the process down, which is exactly what "no input may cause a
    /// panic" forbids.
    #[error("the export nests more than {limit} levels deep")]
    ImportTooDeeplyNested {
        /// The limit.
        limit: usize,
    },

    /// The export is structurally wrong: not the expected format, a missing field, a value of the
    /// wrong kind.
    #[error("the export is malformed: {reason}")]
    ImportMalformed {
        /// What is wrong, in one phrase. Never carries export content.
        reason: &'static str,
    },

    /// The export declares a version this library does not read.
    #[error("the export declares version {version}; at most {supported} is read")]
    ImportUnsupportedVersion {
        /// The version in the file.
        version: u64,
        /// The highest version this library reads.
        supported: u64,
    },

    /// The export is encrypted and this call carried no password.
    #[error("the export is encrypted; a password is required")]
    ImportPasswordRequired,

    /// The export is encrypted in a way this reader cannot open.
    ///
    /// Distinct from [`Error::ImportPasswordRequired`], which means "give me a password": here a
    /// password was given and there is no slot it could open - the export is locked to the
    /// platform key store or to a biometric prompt of the device that wrote it.
    #[error("the export is encrypted with a method this reader cannot use: {reason}")]
    ImportEncryptionUnsupported {
        /// What is missing, in one phrase.
        reason: &'static str,
    },

    /// The password does not open the encrypted export.
    ///
    /// **One error for every failing slot**: whether the password is wrong or a slot was tampered
    /// with is not something the reader can tell apart, and a message that guessed would be wrong
    /// half the time.
    #[error("the password does not open this export")]
    ImportWrongPassword,

    /// The export decrypted but its contents do not open.
    ///
    /// Distinct from [`Error::ImportWrongPassword`] on purpose, because it means something else
    /// to the user: the password was accepted (a slot authenticated), so the **database** is
    /// damaged or was modified after it was written.
    #[error(
        "the export was decrypted but its contents do not open: the file is damaged or was modified"
    )]
    ImportCorrupted,

    /// The key derivation parameters of an encrypted export are outside the accepted range.
    ///
    /// Refused **before** the derivation runs: those numbers come from the file, they decide how
    /// much memory and time the derivation costs, and the reference implementation does not bound
    /// them.
    #[error("the export's key derivation parameters are out of range: {reason}")]
    ImportInvalidKdfParameters {
        /// Which parameter, and why it is refused.
        reason: &'static str,
    },

    /// An encrypted export was asked for without a password.
    ///
    /// The caller decides this before calling [`crate::export::export`] with
    /// [`crate::export::ExportFormat::needs_password`]; reaching this error means the decision
    /// was made wrongly, and the alternative - writing an unencrypted file because no password
    /// arrived - would be a silent downgrade of something the user asked to protect.
    #[error("an encrypted export needs a password")]
    ExportPasswordRequired,

    /// The password given for an encrypted export is empty.
    ///
    /// Refused rather than accepted: an empty password is one anybody can guess by trying
    /// nothing at all, and the file holds every secret in the vault.
    #[error("an encrypted export needs a password that is not empty")]
    ExportPasswordEmpty,

    /// An entry's URI does not fit a QR code, so the HTML export cannot draw it.
    ///
    /// Reported with the entry's **position** and nothing else: an error message ends up in a
    /// log, and the entry's name and issuer are the user's own account data.
    #[error("the URI of the entry at position {position} does not fit a QR code")]
    ExportQrTooLong {
        /// Where in the export the entry was, counting from 1.
        position: usize,
    },

    /// The vault is larger than the container of an encrypted export.
    ///
    /// AES-256-GCM caps a message at 2^36 - 32 bytes, and the whole database goes into one
    /// message. A vault would have to hold tens of gigabytes of entries to reach it.
    #[error("the vault is larger than one encrypted message can hold")]
    ExportTooLarge,

    /// A fixed parameter of an export format was refused by the code that implements it.
    ///
    /// Unreachable in practice: the parameters are constants of the format, and a test pins that
    /// the implementations accept them. It is an error rather than a panic because this library
    /// does not panic, and rather than an `unwrap` because an unwrap in a library is a crash
    /// waiting for the one build where the constant was edited.
    #[error("the export could not be written: a fixed parameter was refused ({parameter})")]
    ExportParameterRefused {
        /// Which parameter, in one phrase.
        parameter: &'static str,
    },

    /// A portable vault file (`.q2fa`) does not begin with a magic this library knows.
    ///
    /// The three shapes are the plain vault container, the passphrase-protected one, and the
    /// old key-only recovery file. A caller that expected a backup and got something else is
    /// told so before any password is asked for.
    #[error("the file is not a portable vault this library writes")]
    PortableBadMagic,

    /// A portable vault file declares a container version this library does not read.
    #[error("the portable vault declares version {version}, which this build does not read")]
    PortableUnsupportedVersion {
        /// The version in the file.
        version: u8,
    },

    /// A portable vault file ends before the length its header declares.
    ///
    /// Checked before the payload is allocated: the length comes from the file and is
    /// attacker-controlled.
    #[error("the portable vault is truncated")]
    PortableTruncated,

    /// A portable vault file is longer or shorter than its lengths add up to.
    ///
    /// Refused rather than ignored: trailing bytes mean the file was appended to or assembled
    /// from parts, and silently reading the first part would hide that.
    #[error("the portable vault holds content beyond the lengths its header declares")]
    PortableLengthMismatch,

    /// A portable vault payload is larger than this library accepts.
    #[error("the portable vault payload is {actual} bytes; at most {limit} are read")]
    PortableTooLarge {
        /// The limit.
        limit: usize,
        /// The size the header declares.
        actual: usize,
    },

    /// The file is a bare vault file, which carries ciphertext but **no master key**.
    ///
    /// It looks like a backup and is not one: importing it would replace the local vault with
    /// ciphertext the local key probably cannot open. The caller is told so it can say what to
    /// do (export a vault backup instead), rather than leaving the user with a vault that
    /// cannot be read.
    #[error("this is a bare vault file and carries no master key")]
    PortableVaultFileWithoutKey,

    /// A passphrase-protected portable vault was opened without a password.
    #[error("this portable vault is protected by a passphrase")]
    PortablePasswordRequired,

    /// The plaintext structure of a vault entry contains a duplicated field node.
    ///
    /// Implementations disagree on whether the first or the last occurrence wins: a classic
    /// parsing ambiguity, and an attack surface — an attacker can append an overriding node after
    /// a legitimate one.
    #[error("vault entry contains a duplicate field (tag {tag:#04x})")]
    VaultDuplicateField {
        /// The field tag that appears more than once.
        tag: u8,
    },

    /// The plaintext structure of a vault entry is corrupt (missing required field, wrong field
    /// length, and so on).
    ///
    /// Note that this error can only occur **after authentication has succeeded** — the AEAD tag
    /// covers the whole plaintext, so successful decryption means the plaintext is the one that
    /// was written. Reaching it means the writing side produced an invalid structure (a bug in
    /// this library), or the key comes from an implementation of another version. **A parser
    /// called directly with arbitrary plaintext can trigger it as well**, since such a call
    /// bypasses the AEAD.
    #[error("vault entry structure is corrupt")]
    VaultCorrupt,

    /// A text field of a vault entry is not valid UTF-8.
    ///
    /// **Rejected rather than lossily replaced**: replacement turns corrupt data into an entry
    /// that looks normal but has different content, and the user never learns that the account
    /// name was changed.
    #[error("a text field of the vault entry is not valid UTF-8")]
    VaultInvalidUtf8,

    /// Vault decryption or authentication failed.
    ///
    /// **It does not distinguish** a wrong master key, tampered ciphertext and an AAD mismatch,
    /// for two reasons:
    ///
    /// - **Useful to an attacker**: telling them apart is an oracle that reveals whether a
    ///   guessed key is correct, or which part was modified.
    /// - **Useless to the user**: all three call for exactly the same action — this vault cannot
    ///   be opened.
    ///
    /// Whether the wrong master key was picked is something the layer above decides from where
    /// the key came from; the cryptographic layer need not leak anything for that.
    #[error("cannot decrypt the vault: master key mismatch or the file has been tampered with")]
    VaultDecryptionFailed,

    /// The master key has the wrong length.
    #[error("master key must be {expected} bytes, but is {actual} bytes")]
    MasterKeyWrongLength {
        /// Required length.
        expected: usize,
        /// Actual length.
        actual: usize,
    },

    /// A variable-length field of a vault entry exceeds the limit.
    ///
    /// The limit cannot be enforced **before** decryption from the ciphertext length (that length
    /// says nothing about the field length), so it must be checked while parsing after
    /// decryption. See [`crate::vault::Entry::MAX_FIELD_LEN`].
    #[error("field {field} is too long: limit {limit} bytes, {actual} bytes given")]
    FieldTooLong {
        /// Field name (a fixed string, never user data).
        field: &'static str,
        /// Allowed limit.
        limit: usize,
        /// Actual length.
        actual: usize,
    },

    /// Reading or writing a vault file failed.
    ///
    /// It carries only the **operating system error description**, never file content — `reason`
    /// comes from `std::io::Error`, which does not include the bytes that were written.
    #[error("vault file read/write failed: {reason}")]
    VaultIo {
        /// Operating system error description.
        reason: String,
    },

    /// A device identity public key is invalid.
    ///
    /// Public keys come from external input (QR codes, the network) and must be validated before
    /// use. **Invalid-curve attacks** are real: handing over a point that is not on the curve but
    /// lies in a small subgroup can leak private-key information through the peer's computation.
    /// This error is therefore part of the security boundary, not a format check.
    ///
    /// `reason` is a fixed internal description and **contains no raw input bytes** — they may
    /// come from an attacker, and putting them into an error message turns logs into an injection
    /// point.
    #[error("invalid device public key: {reason}")]
    DevicePublicKeyInvalid {
        /// Fixed reason description.
        reason: &'static str,
    },

    /// A device identity signature is malformed or fails verification.
    ///
    /// **A malformed signature and a failed verification deliberately share this variant.** The
    /// caller's response is identical (reject this authentication), and telling them apart would
    /// only give an attacker a small oracle.
    #[error("invalid device signature: {reason}")]
    DeviceSignatureInvalid {
        /// Fixed reason description.
        reason: &'static str,
    },

    /// The pairing payload (QR code content) is structurally invalid.
    ///
    /// Separate from [`Error::PairingUnsupportedVersion`]: a wrong length or a missing required
    /// field is damage **this version can judge**, whereas an unrecognized version is something
    /// this version **cannot read**. For the user the advice differs — "regenerate the QR code"
    /// versus "upgrade the app" — so the two are not merged.
    ///
    /// `reason` is a fixed internal description and **contains no input bytes**: QR code content
    /// may come from an attacker.
    #[error("invalid pairing payload: {reason}")]
    PairingPayloadMalformed {
        /// Fixed reason description.
        reason: &'static str,
    },

    /// The pairing payload protocol version is not supported.
    ///
    /// It must be **rejected outright** rather than interpreted as best as possible: reading a
    /// future version's fields under this version's layout would turn a "this operation is
    /// forbidden" written by the future version into "allowed".
    #[error("unsupported pairing protocol version: {version}")]
    PairingUnsupportedVersion {
        /// Version declared in the payload.
        version: u8,
    },

    /// Pairing message authentication failed.
    ///
    /// **Tampered ciphertext, a wrong tag, a message from another session and a joiner using the
    /// wrong public key** deliberately share this variant. The caller's response is identical
    /// (this pairing failed, scan the code again), and telling them apart would give an attacker
    /// an oracle to probe with.
    #[error(
        "pairing message authentication failed: tampered ciphertext, or not part of this pairing"
    )]
    PairingAuthenticationFailed,

    /// The recovery file structure is invalid.
    ///
    /// Separate from [`Error::RecoveryAuthenticationFailed`] because the two mean completely
    /// different things to the **user**: this variant says "wrong file / broken file", while that
    /// one says "wrong passphrase". Merging them makes the user retry the passphrase in a
    /// direction where retrying cannot help.
    ///
    /// `reason` is a fixed internal description and **contains no input bytes**.
    #[error("invalid recovery file: {reason}")]
    RecoveryFileMalformed {
        /// Fixed reason description.
        reason: &'static str,
    },

    /// The derivation parameters of the recovery file are invalid.
    ///
    /// These parameters **come from the file itself** and are therefore untrusted input. Without
    /// this validation, a file edited to say `m_cost = u32::MAX` would turn an import into a
    /// memory-exhaustion attack.
    #[error("invalid recovery file derivation parameters: {reason}")]
    RecoveryParametersInvalid {
        /// Fixed reason description.
        reason: &'static str,
    },

    /// The passphrase is empty.
    ///
    /// **Rejected outright rather than accepted as a weak passphrase**: accepting it would hand
    /// the user, behind a screen that looks successful, a backup that can be opened in about a
    /// second.
    #[error("recovery passphrase must not be empty")]
    RecoveryPassphraseEmpty,

    /// Authentication of the recovery file failed: wrong passphrase, or a tampered file.
    ///
    /// The two causes deliberately share this variant (same reasoning as
    /// [`Error::PairingAuthenticationFailed`]).
    #[error(
        "recovery file authentication failed: wrong passphrase, or the file has been tampered with"
    )]
    RecoveryAuthenticationFailed,

    /// The encryption step of the recovery file failed.
    ///
    /// It can only come from an AEAD implementation limit (plaintext or AAD too long) and does
    /// not happen with the parameters in use; it is listed separately so that this case is not
    /// misreported as a wrong passphrase.
    #[error("recovery file encryption failed")]
    RecoveryEncryptionFailed,

    /// The Argon2id computation failed.
    ///
    /// The most common real cause is **out of memory**: the default parameters allocate 64 MiB
    /// at once.
    #[error("passphrase derivation failed (possibly out of memory)")]
    RecoveryKdfFailed,

    /// The version of a persisted format is not supported.
    ///
    /// Used for data that is **kept for a long time**, such as recovery files: when a file written
    /// by a future version reaches an older one, it must be **rejected outright** instead of being
    /// interpreted under the current layout. The latter would turn "the new version improved
    /// security" into "the older version accepted it under a weaker interpretation".
    #[error("unsupported format version: {version}")]
    UnsupportedFormatVersion {
        /// Version declared in the file.
        version: u8,
    },

    /// A challenge-response message is structurally invalid.
    ///
    /// A wrong length, or a carried public key that is not a valid curve point. **This is a
    /// different thing from [`Error::AuthProofFailed`]**: this variant says the message is not
    /// even well-formed, that one says the message is well-formed but the peer cannot compute the
    /// correct tag.
    ///
    /// `reason` is a fixed internal description and **contains no input bytes**.
    #[error("invalid authentication message: {reason}")]
    AuthMessageMalformed {
        /// Fixed reason description.
        reason: &'static str,
    },

    /// The proof or confirmation tag of the challenge-response does not match.
    ///
    /// It means "the peer failed to prove that it holds the master key". A tampered tag, an
    /// inconsistent session identifier, or a peer that has no master key at all — the three causes
    /// deliberately share this variant, because the caller's response is identical (declare this
    /// authentication failed and disconnect) and telling them apart would give a probeable signal.
    #[error("authentication failed: the peer did not prove possession of the master key")]
    AuthProofFailed,

    // ── Orchestration (`crate::flow`) ─────────────────────────────────────────
    /// This device has no device identity yet, and this step needs one.
    ///
    /// Different from "creating the identity failed": this is a caller asking for a signature
    /// before obtaining an identity — a call-order error, not a platform capability problem.
    #[error("this device has no device identity yet; obtain one before signing")]
    DeviceKeyMissing,

    /// This device has never registered or logged in.
    ///
    /// Deliberately separate from "a master key exists but cannot be read": the former is the
    /// normal path (send the user to register or log in), the latter means data may already be
    /// damaged. Sharing one error would make the UI treat the latter as "not logged in yet" and
    /// send the user to **register again**, permanently losing the existing data.
    #[error("this device is not registered or logged in")]
    DeviceNotRegistered,

    /// The declared device identity is not the local one.
    #[error(
        "device identity mismatch: the peer's declared identity differs from the locally obtained one"
    )]
    DeviceIdentityMismatch,

    /// Writing the master key to platform storage failed.
    ///
    /// `reason` is a **fixed string** and must not contain key material: it is logged, and this is
    /// one of the very few paths that touch the master key.
    #[error("cannot write the master key to platform storage: {reason}")]
    SecureStoreWriteFailed {
        /// Developer-facing reason, containing no secret.
        reason: &'static str,
    },

    /// The timestamp is `0`.
    ///
    /// `0` usually means the caller forgot to pass a time (this library never reads a clock; time
    /// always comes from the caller). Letting such a value into the vault pollutes the
    /// time-ordered merge logic, and the result is consistently wrong and hard to trace.
    #[error("timestamp must not be 0")]
    TimestampZero,

    // ── Sync ──────────────────────────────────────────────────────────────────
    /// The magic number of the sync payload does not match.
    ///
    /// Separate from "the payload is corrupt": a bad magic usually means **this is not a sync
    /// payload at all** (the user picked the wrong file, or another protocol's data was fed in),
    /// which points the investigation in a completely different direction than "a payload
    /// produced by this application is broken".
    #[error("not a Qualia2FA sync payload")]
    SyncBadMagic,

    /// The sync payload format version is not supported.
    #[error("unsupported sync payload version {version}")]
    SyncUnsupportedVersion {
        /// Version declared by the payload.
        version: u8,
    },

    /// The payload is empty.
    ///
    /// Reported whether it is discovered in the compression layer or in the outer envelope.
    /// "There is no payload at all" and "the payload is broken" point in completely different
    /// directions when investigating: the former is usually a caller passing an empty buffer, the
    /// latter a peer or transport problem.
    #[error("sync payload is empty")]
    SyncEmptyPayload,

    /// The payload is truncated.
    #[error("sync payload is truncated")]
    SyncTruncated,

    /// The record count declared in the payload does not match its actual content.
    ///
    /// Separate from [`Error::SyncTruncated`]: truncation means "not enough bytes", this one means
    /// "enough bytes, but they do not add up" — the payload was reassembled, a stronger signal
    /// than truncation.
    #[error("sync payload declares {declared} records but only {actual} were decoded")]
    SyncRecordCountMismatch {
        /// Record count declared by the payload.
        declared: usize,
        /// Record count actually decoded.
        actual: usize,
    },

    /// The payload contains more records than the limit allows.
    #[error("sync payload record count {count} exceeds the limit {limit}")]
    SyncTooManyRecords {
        /// Record count declared by the payload.
        count: usize,
        /// Allowed limit.
        limit: usize,
    },

    /// Compression failed.
    ///
    /// Deflate is defined for every input, so this does not occur in practice. It exists so that
    /// the return value of `miniz_oxide` is not `unwrap`ped.
    #[error("sync payload compression failed")]
    SyncCompressionFailed,

    /// The decompressed content exceeds [`MAX_DECOMPRESSED_LEN`], or the input is not a valid
    /// deflate stream at all.
    ///
    /// [`MAX_DECOMPRESSED_LEN`]: crate::sync::compress::MAX_DECOMPRESSED_LEN
    ///
    /// Corruption, truncation and a length mismatch deliberately share one variant: their handling
    /// is identical (reject this sync, ask the peer to resend), and separating them has no
    /// actionable value for the user.
    #[error("sync payload decompression failed")]
    SyncDecompressionFailed,

    /// The payload exceeds the length limit after decompression.
    ///
    /// # Why it is separate from [`Error::SyncDecompressionFailed`]
    ///
    /// Because it is the only cause in that group that does **not** represent an attack. A user who
    /// really has seventy thousand entries will hit the limit, and telling them "the payload is
    /// corrupt" would send them to check the network, the devices and the pairing — none of which
    /// is the problem. Telling them "too large, use the LAN instead" is actionable.
    ///
    /// The price is that an attacker can probe the limit's position with one bit, and the limit is
    /// in the open-source code anyway. A related fact: decompression happens **after** the outer
    /// AEAD, so input reaching this point has already been authenticated.
    #[error(
        "sync payload exceeds the {limit} byte limit after decompression; use LAN mode instead"
    )]
    SyncPayloadTooLarge {
        /// The limit, attached to the error so callers need not look up the constant.
        limit: usize,
    },

    /// The payload contains an unknown record kind.
    ///
    /// As with the equivalent vault-file error, an unknown kind is rejected rather than skipped:
    /// skipping makes semantics added by a future version **silently disappear** on older
    /// versions, and "the sync finished but a few entries are missing" is one of the hardest
    /// failures to trace.
    #[error("sync payload contains an unknown record kind {value:#04x}")]
    SyncUnknownRecordKind {
        /// The kind byte that was read.
        value: u8,
    },

    /// The payload contains an unexplained field or structure.
    ///
    /// This variant is the **catch-all**: every structural problem that can be named has its own
    /// variant, so reaching this one means "the payload failed a self-consistency check, but which
    /// one cannot be said".
    #[error("malformed sync payload: {reason}")]
    SyncMalformed {
        /// Human-readable reason for logs and diagnostics. **Must not contain secret material.**
        reason: &'static str,
    },

    /// Authentication of the payload's outer layer failed.
    ///
    /// Separate from [`Error::VaultDecryptionFailed`]: that one means "the vault file cannot be
    /// opened", this one means "this sync payload is untrustworthy". The client handles them
    /// differently — the former asks the user to check the master key, the latter only needs "this
    /// sync failed, please retry".
    ///
    /// **It does not distinguish** a wrong master key, a tampered payload and a mismatched sender
    /// identifier: telling them apart helps an attacker and has no actionable value for the user.
    #[error("sync payload authentication failed")]
    SyncAuthenticationFailed,

    /// The vault holds entries with icons and the channel cannot carry them.
    ///
    /// An icon is a picture of up to 64 KiB, and a channel with a declared message limit (a QR
    /// code, for instance) cannot hold a payload that carries one. The refusal happens **before
    /// anything is sealed**, so the user is told "this channel cannot move icons" instead of
    /// seeing a capacity error that says nothing about icons, and the icon is never silently
    /// dropped: a sync that quietly loses what the user sees is worse than one that is refused.
    ///
    /// The fix is not to shrink the icon here: the byte-stream channel (a LAN connection) has no
    /// message limit and carries the vault as it is.
    #[error("this channel cannot carry entries with icons; use a connection without a size limit")]
    SyncIconRequiresByteTransport,

    /// This sync payload has already been processed.
    ///
    /// Replaying an old payload is harmless in itself (merging is idempotent), but **doing a full
    /// decryption and merge for nothing** is real cost, and it misleads the "last synced at" shown
    /// in the UI. Payload identifiers that have been seen are therefore remembered, and duplicates
    /// rejected.
    ///
    /// This is a **separate error** rather than a silent success: the caller needs to know "the
    /// sync did happen, this one is a duplicate", not "a sync just succeeded".
    #[error("this sync payload has already been applied")]
    SyncAlreadyApplied,

    /// The log of used payload identifiers is full.
    ///
    /// Failing explicitly beats silently dropping the oldest entry: a silent drop makes a very old
    /// payload acceptable again, which is exactly what replay protection must prevent. On seeing
    /// this error the caller should tell the user that the sync history is too long; what to do
    /// about it is a higher-level policy decision.
    #[error("the log of used sync payload identifiers is full (limit {limit})")]
    SyncIdLogFull {
        /// Maximum number of entries allowed.
        limit: usize,
    },

    // ── Transport layer ──
    /// The transport channel itself failed (disconnect, timeout, platform refusal).
    ///
    /// # Why the underlying error is not passed through
    ///
    /// The underlying failures are things like `std::io::Error` or platform permission errors —
    /// **abstractions that do not belong to this crate**. This crate has
    /// `#![forbid(unsafe_code)]` and depends on no I/O, so writing those types into the error enum
    /// would freeze platform details into the protocol layer. Only an opaque `reason` is kept — it
    /// is meant for logs, not for program decisions.
    #[error("transport failed: {reason}")]
    TransportFailed {
        /// Opaque description for logs.
        reason: &'static str,
    },

    /// The device identifier reported by the peer disagrees with the sender claimed by the
    /// transport channel.
    ///
    /// # Why this check must exist
    ///
    /// The `sender` inside the payload is **self-reported**, and its presence in the AAD only
    /// guarantees that no third party changed it. On a broadcast channel (LAN multicast) any
    /// device can replay a payload **signed by somebody else** verbatim, so the payload says B
    /// while C actually sent it. This check takes "who sent this" from the transport channel and
    /// compares it with the value the payload claims.
    ///
    /// Note that it stops **impersonation**, not replay — replay is stopped by
    /// [`Error::SyncAlreadyApplied`].
    #[error("the sender reported by the payload differs from the sender claimed by the channel")]
    SyncSenderMismatch,

    /// The kind claimed by the payload is not one this version knows.
    ///
    /// Separate from [`Error::SyncUnknownRecordKind`]: that one is about the kind of **one record
    /// inside** the payload (entry or tombstone), this one about the kind of **the whole payload**
    /// (state exchange or request). See [`crate::sync::PayloadKind`].
    #[error("unknown payload kind {value:#04x}")]
    SyncUnknownPayloadKind {
        /// Raw byte from the wire format.
        value: u8,
    },

    /// The transport channel does not support this operation.
    ///
    /// For example, a channel that can carry only a single message (a QR code) is asked to open a
    /// long-lived connection. It is **not** used for "this channel cannot fit the payload" — that
    /// is [`Error::TransportMessageTooLarge`], and the two are handled quite differently (the
    /// former can only switch channels; the latter can switch modes or send the user to the LAN).
    #[error("the transport channel does not support this operation: {operation}")]
    TransportUnsupported {
        /// Name of the rejected operation.
        operation: &'static str,
    },
    /// The one-shot channel has already been used.
    ///
    /// A QR code is the typical one-shot channel: one code carries exactly one exchange. Treating
    /// it as reusable would turn "scan the same code twice" into two syncs, which is a side path
    /// around replay protection.
    #[error("this transport channel has already been used and cannot be reused")]
    TransportAlreadyUsed,

    /// A single message exceeds what the channel can carry.
    ///
    /// The usual trigger is a QR code: it is a **fixed-capacity** channel, so when the message does
    /// not fit the only options are switching mode or switching channel. The caller should use this
    /// to steer the user towards the LAN, not truncate the payload — a truncated payload fails
    /// AEAD, so what the user sees is "corrupted data".
    #[error("a single message needs {needed} bytes, exceeding this channel's {limit} byte limit")]
    TransportMessageTooLarge {
        /// Number of bytes this message needs.
        needed: usize,
        /// Limit declared by the channel.
        limit: usize,
    },

    /// No joinable sync session was found.
    ///
    /// Separate from "found one, but the handshake failed": the former is the normal "nobody
    /// nearby", where the caller should let the user retry or check the network; only the latter is
    /// an anomaly.
    #[error("no joinable sync session was found")]
    SyncNoSessionFound,
}

/// The unified result type of this library.
pub type Result<T> = core::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    /// The displayed error text must contain the numbers needed to locate the problem, and must
    /// not panic.
    #[test]
    fn display_includes_diagnostic_numbers() {
        let cases: [(Error, &str); 3] = [
            (Error::Base32InvalidCharacter { index: 7 }, "7"),
            (Error::Base32InvalidLength { length: 3 }, "3"),
            (
                Error::SecretTooShort {
                    required: 20,
                    actual: 4,
                },
                "20",
            ),
        ];
        for (err, needle) in cases {
            let text = err.to_string();
            assert!(
                text.contains(needle),
                "error text {text:?} does not contain {needle:?}"
            );
        }
    }

    /// `Error` must implement `std::error::Error`, so that callers can chain it with `?` and
    /// `source()`.
    #[test]
    fn implements_std_error() {
        fn assert_is_std_error<E: std::error::Error>() {}
        assert_is_std_error::<Error>();
    }
}
