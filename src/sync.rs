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

//! Envelope for sync payloads: serialize → compress → whole-payload AEAD.
//!
//! # Responsibility
//!
//! Turn "one device's entries and tombstones" into a byte string that can be carried over
//! any channel, and back again. It does not know whether a payload travels by QR code, over
//! a LAN, or by some other means, nor who the peer is: this layer is transport-agnostic and
//! depends on no transport module.
//!
//! # Three layers, and what each of them stops
//!
//! ```text
//! ┌─ outer envelope (plaintext header + whole-payload AEAD) ─────────┐
//! │  magic 8 | version 1 | kind 1 | sync_id 32 | device ID 32        │
//! │  nonce 24 | ciphertext (including authentication tag)            │
//! │  ┌─ inner: compression ──────────────────────────────────┐       │
//! │  │  ┌─ payload plaintext ───────────────────────────┐    │       │
//! │  │  │ record count 4 | record × N                   │    │       │
//! │  │  │   each: entry_id 16 | nonce 24 | len 4 | ct   │    │       │
//! │  │  └───────────────────────────────────────────────┘    │       │
//! │  └───────────────────────────────────────────────────────┘       │
//! └──────────────────────────────────────────────────────────────────┘
//! ```
//!
//! The remainder of the plaintext header (magic, version, kind, `sync_id`, device ID)
//! serves as the outer AAD as a whole, so on the wire those fields appear exactly once.
//!
//! - **Inner per-record AEAD** (kind + `entry_id` + format version in the AAD): stops
//!   moving the ciphertext of entry A into the slot of entry B, and stops presenting a
//!   tombstone as an entry. Its key is **not** the record key of the vault file (the HKDF
//!   salt differs), so ciphertexts of the two domains cannot be opened across domains. See
//!   [`derive_record_key`]. Merging accepts records one at a time and stores them verbatim,
//!   so this per-record binding is what keeps a stored record matching its identifier.
//! - **Outer whole-payload AEAD**: stops splicing together parts of two different
//!   payloads. Per-record authentication cannot detect such a splice, because every record
//!   is valid on its own. The outer AAD covers the entire plaintext header, so moving any
//!   of those fields makes the outer authentication fail.
//! - **Compression** takes part in no security property; it only makes the bytes shorter.
//!
//! # The plaintext carries no record kind
//!
//! Whether a record is a live entry or a tombstone is written only in the **inner AAD**,
//! not in the payload plaintext. The cost is that opening a record tries both kinds (see
//! [`record`]); the benefit is that not even the number of deletions in a sync is visible,
//! and the existence of a deletion is itself sensitive information. `RECORD_HEADER_LEN`
//! therefore counts no kind byte.
//!
//! # Replay
//!
//! Every payload carries a 32-byte random `sync_id`. Merging is idempotent (merging the
//! same data twice yields the same result), so a replay does not break correctness; it does
//! waste a full decryption and merge, and it lets an attacker move the "last sync time"
//! shown in the UI to any value. [`SeenSyncIds`] therefore records the identifiers that
//! were processed, and rejects repeats outright.

mod adjudicate;
pub mod compress;
mod merge;
pub mod record;
mod seen;

use crate::vault::crypto;
use crate::vault::{EntryId, MasterKey, NONCE_LEN, TAG_LEN};
use crate::{Error, Result};
pub use adjudicate::{Adjudicated, Decision, adjudicate};
pub use merge::{
    Conflict, ConflictKind, HasEntryId, MergeOutcome, MergedRecord, RecordSet, merge_into,
};
use qualia_dik::{DEVICE_ID_LEN, DeviceId};
pub use record::{OpenedRecord, open as open_record, seal_entry, seal_tombstone};
pub use seen::{MAX_SEEN_SYNC_IDS, SeenSyncIds};

/// Payload magic. 8 ASCII bytes, chosen to be recognizable in a hex editor.
pub const MAGIC: &[u8; 8] = b"Q2FASYNC";

/// Payload format version currently written.
///
/// **Fully independent** of [`crate::vault::FORMAT_VERSION`]: that one governs the layout of
/// vault files, this one the layout of payloads. The two evolve separately; binding "the
/// payload format changed" to "the file format changed" would make any change in one of them
/// require a statement from the other.
///
/// # Version 1 → 2: the payload kind joined the outer AAD
///
/// The version 1 AAD was only `magic || version || sync_id || sender`, so a payload asking
/// the peer to send its vault and a payload saying "this is my full state" were
/// **indistinguishable in the outer layer**. With an empty record set both even had exactly
/// the same byte structure, leaving the receiver to guess from convention — and the wrong
/// guess ("an empty full state" read as a request) makes both sides wait for the other to
/// start.
///
/// Version 2 states this explicitly in [`PayloadKind`] and binds it into the AAD: the kind is
/// therefore **authenticated** and a third party cannot change it.
///
/// # Version 2 → 3: entries may carry fields the older format could not express
///
/// Version 3 payloads transport entries whose plaintext may contain node tags an older
/// version does not know: the entry kind (TOTP / HOTP / mOTP / Yandex OTP / Steam Guard) and
/// the two PIN fields. An older peer would skip those nodes by their length and store a
/// **mis-typed entry** — an mOTP entry silently becoming TOTP, with a code that never
/// works — so mixing versions is refused rather than tolerated.
///
/// Nothing else about the payload layout changed: the only difference is the number, which
/// takes part in both the outer and the inner AAD.
///
/// # Version 3 → 4: the group tree, the icon, and u32 length prefixes
///
/// Three shapes changed at once, and all three are why a version 3 peer must refuse the payload
/// rather than skip what it does not know:
///
/// - A group plaintext now carries one ordered child list (entries and child groups mixed)
///   instead of a flat position and an entry list. An older peer would find neither of the nodes
///   it needs.
/// - An entry plaintext may carry an icon node. An older peer would skip it by its length, keep
///   the entry without its picture, and write that loss back into its own vault - a silent one,
///   which is the worst kind.
/// - The length prefix of both plaintext headers is now a **u32**. An icon of up to 64 KiB, or a
///   group whose child list approaches 64 KiB, does not fit a u16: it would be refused as
///   malformed on both sides of a payload that is otherwise fine. The prefix width is part of the
///   version for the same reason as the rest: a version 3 record would be read with the wrong
///   width.
///
/// # It also takes part in the **inner** record AAD
///
/// Changing it makes the inner records of existing payloads unopenable. That is what stops
/// cross-version transplanting: an inner record of an older version must not be moved into a
/// newer payload.
pub const FORMAT_VERSION: u8 = 4;

/// Payload version number used only by version 1.
///
/// **No version 1 payload has ever existed**: that format was never released. The constant
/// has exactly one purpose — giving "version 1 input must be rejected explicitly" a name to
/// refer to, so a test can pin it down. No path reconstructing the version 1 AAD is provided
/// on purpose: the version 1 and version 2 AADs differ in length, so `open` would grow a
/// branch selecting the AAD length from the input version, and no real input could ever
/// reach it.
///
/// This does not contradict "only grows" in [`crate::vault::READABLE_VERSIONS`]: that rule
/// covers **user files** (a user holds old files and must keep being able to open them).
/// Payloads are transient — they never touch disk and need not survive across versions.
///
/// Only tests use it, so the constant is `#[cfg(test)]`. A `pub(crate)` constant does **not**
/// trigger `dead_code` in a library build, so `expect(dead_code, ...)` would be an
/// unfulfilled expectation and `-D warnings` rejects it.
#[cfg(test)]
pub(crate) const LEGACY_FORMAT_VERSION_1: u8 = 1;

/// What a payload **asks the peer to do**.
///
/// Separate from the `vault` record kind, which describes one record **inside** a payload
/// (entry or tombstone); this one describes the payload as a whole.
///
/// It takes part in the outer AAD and is therefore authenticated. The kind decides whether
/// the receiver **sends a payload back**, and an unauthenticated one could be changed by a
/// third party into a request that makes the receiver send its entire vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadKind {
    /// The sender's **full state**: accept it and merge.
    Vault,
    /// The sender's **request**: send me your full state.
    ///
    /// A request carries **no** records: "what I want" is a **set**, and in real use that set
    /// is "everything". The receiver answers with [`Payload::from_vault`]. Incremental sync
    /// will add a list of wanted IDs here rather than introduce a different format — the same
    /// convention described on [`Payload::from_vault`].
    ///
    /// It is a distinct variant rather than "an empty payload means a request": a freshly
    /// registered device with no entries yet sends a full sync whose payload is **also**
    /// empty.
    Request,
}

impl PayloadKind {
    /// Byte value on the wire.
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        match self {
            Self::Vault => 0x01,
            Self::Request => 0x02,
        }
    }

    /// Restore from a wire byte.
    #[must_use]
    pub const fn from_byte(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(Self::Vault),
            0x02 => Some(Self::Request),
            _ => None,
        }
    }
}

/// Length of the payload plaintext header: magic + version + kind + sync_id + sender.
///
/// It holds no field beyond "who the sender is" — the sender identifier is in the header
/// because it is part of the outer AAD (authenticated but not secret, see
/// [`Payload::sender`]).
///
/// The field is a [`DeviceId`] (32 bytes, the SHA-256 of the device identity public key),
/// not the 16-byte [`EntryId`]: `EntryId` identifies **a record in the vault** and is random,
/// while [`DeviceId`] identifies **a device** and is what "who is talking to me" resolves to.
pub const HEADER_LEN: usize = MAGIC.len() + 1 + 1 + SYNC_ID_LEN + DEVICE_ID_LEN;

/// Length of a payload identifier.
///
/// 256-bit, as wide as an entry ID: it needs collision resistance, not resistance to
/// guessing (knowing someone else's payload identifier is of no use — the payload itself is
/// protected by AEAD).
pub const SYNC_ID_LEN: usize = 32;

/// Identifier of one sync.
///
/// Generated randomly by the initiator and used by the **receiver** to recognize duplicate
/// payloads. It is not a secret.
pub type SyncId = [u8; SYNC_ID_LEN];

/// Length of the fixed part of one record in the payload plaintext: `entry_id` + nonce +
/// ciphertext length.
///
/// The record kind byte is part of the inner AAD, but **not** of the plaintext, so not even
/// the number of deletions in a sync is visible; opening a record tries both kinds (see the
/// module documentation of [`record`]).
///
/// The parser does not depend on this constant — it reads records by their length prefix.
/// [`Record::encoded_len`] does, so the constant must count exactly the bytes the framing
/// actually writes.
const RECORD_HEADER_LEN: usize = EntryId::LEN + NONCE_LEN + 4;

/// Maximum number of records allowed in a payload.
///
/// Shares its origin with [`crate::vault::MAX_RECORDS`] for vault files but is a separate
/// constant: the two are **different** limits (a file is local storage, a payload arrives
/// over the network). Defining them separately means relaxing one does not relax the other.
pub const MAX_RECORDS: usize = 1_000_000;

/// Length limit of the payload plaintext (**before** compression).
///
/// The record count limit together with actual record lengths decides this value; the
/// decompression layer has a limit of its own ([`compress::MAX_DECOMPRESSED_LEN`]) and both
/// must pass. This one bounds payloads **we generate**, rejecting obviously unreasonable
/// data sets while they are being built.
pub const MAX_PLAINTEXT_LEN: usize = 64 * 1024 * 1024;

/// HKDF salt used to derive the **sync record** subkey from the master key.
///
/// The two domains are separated at the **key level** by this salt, not by the AAD bytes: the
/// record kind byte and the format version field can hold the same values in both domains, so
/// a compile-time assertion at the end of `sync.rs` checks that the kind bytes do not overlap.
///
/// The vault entry key uses an all-zero salt; changing that derivation would make every
/// existing `.q2fa` file unopenable.
///
/// # The value of this constant is an external contract
///
/// It is 32 ASCII bytes, and changing one character makes every existing sync payload
/// (including those already sent inside QR codes) unopenable. Writing it as a literal
/// 32-byte array rather than a string constant plus an assertion lets the type check of
/// `[u8; 32]` catch a wrong length at **compile time**.
pub const HKDF_SALT_SYNC: [u8; 32] = *b"Qualia2FA sync salt v1 (records)";

/// Derive the **sync record** subkey from the master key.
///
/// It is **not** the vault file entry subkey; see [`HKDF_SALT_SYNC`].
///
/// It is derived once per sync and then passed to every record: a payload can hold tens of
/// thousands of records, and deriving again per record would multiply two HMAC-SHA256
/// computations by the number of entries.
pub fn derive_record_key(master: &MasterKey) -> Result<[u8; 32]> {
    crypto::derive_key_with_salt(master, &HKDF_SALT_SYNC, crypto::HKDF_INFO_SYNC_RECORD)
}

/// Derive the **outer envelope** subkey from the master key.
///
/// Independent of the sync record subkey, of the vault subkeys, and of the check-value
/// derivation. Outer and inner use different keys on purpose: the outer layer encrypts bytes
/// that are **already encrypted per record**, and if the two layers shared one key the inner
/// ciphertext would become part of the outer plaintext — using one key to encrypt both
/// plaintext and ciphertext is a textbook misuse.
pub fn derive_envelope_key(master: &MasterKey) -> Result<[u8; 32]> {
    crypto::derive_key_with_salt(master, &HKDF_SALT_SYNC, crypto::HKDF_INFO_SYNC_ENVELOPE)
}

/// One record in a payload: a per-record ciphertext together with the cleartext information
/// that locates it.
///
/// # A record does not know whether it is an entry or a tombstone
///
/// The kind lives in the ciphertext (it is part of the AAD but **not** of the record
/// header), so not even the number of deletions in a sync is visible. The cost is that
/// opening a record tries both kinds; see the module documentation of [`record`] for the
/// trade-off.
///
/// It carries **ciphertext only**, never decrypted content, so `Clone` does not widen the
/// exposure of key material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// Which entry this record belongs to.
    pub entry_id: EntryId,
    /// Random nonce used to encrypt this record.
    pub nonce: [u8; NONCE_LEN],
    /// Ciphertext, **including** the 16-byte authentication tag.
    pub ciphertext: Vec<u8>,
}

impl merge::HasEntryId for Record {
    /// Which entry this record is about.
    ///
    /// `entry_id` also takes part in the inner AAD, so it is authenticated: an attacker
    /// cannot change a record's identifier to another value and still open it.
    fn entry_id(&self) -> EntryId {
        self.entry_id
    }
}

impl Record {
    /// Number of bytes this record occupies in the payload plaintext.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        RECORD_HEADER_LEN + self.ciphertext.len()
    }
}

/// The content of a payload: every record to be sent this time.
///
/// Records are held in a [`RecordSet`], keyed by [`EntryId`]: union merging treats the same
/// entry appearing twice in one payload as meaningless, so the set type carries the "at most
/// one record per entry" invariant and a duplicate is reported as a structural error while
/// parsing.
///
/// # Record order is deterministic
///
/// [`RecordSet`] is a `BTreeMap` internally and iterates in ascending [`EntryId`] order, so
/// **the same content serializes to a byte-identical plaintext**. That is not the same as
/// "byte-identical payload": every record's nonce is random, so the ciphertexts differ.
/// Determinism is useful for exact byte comparisons in tests and gives a cheap criterion for
/// "do two payloads carry the same data".
#[derive(Debug)]
pub struct Payload {
    /// Identifier of this sync. The receiver uses it to recognize duplicate payloads.
    pub sync_id: SyncId,
    /// The device that started this sync.
    ///
    /// Takes part in the **outer** AAD, so it is authenticated: an attacker cannot change a
    /// payload's sender to somebody else. Merging needs to know who is initiating, because
    /// conflict resolution is decided by the initiator.
    ///
    /// # It is a device identifier, but does **not** take part in device authentication
    ///
    /// The "sender" here is only an authenticated **claim**: it proves that the party
    /// holding the master key claims to be this device. Actually proving the device identity
    /// (private key in hardware) is the job of [`crate::auth`], which is a different path.
    /// Neither replaces the other: this field stops a payload from being attributed to
    /// somebody else, which device authentication does not.
    pub sender: DeviceId,
    /// The records in this payload, **still encrypted**.
    pub records: RecordSet<Record>,
    /// What this payload asks the peer to do.
    ///
    /// Private field: it must **always** match the byte written to the wire format, so only
    /// the constructors set it and a read-only accessor exposes it. Making it public would
    /// allow changing the field without re-running `seal`.
    kind: PayloadKind,
}

impl Payload {
    /// Generate a fresh payload identifier.
    ///
    /// # Errors
    ///
    /// [`Error::RandomnessUnavailable`]: the OS random source is unavailable. There must be
    /// **no** fallback to a userspace PRNG: a predictable payload identifier defeats replay
    /// protection, because an attacker could precompute an identifier that will be accepted
    /// later.
    pub fn new_sync_id() -> Result<SyncId> {
        let mut id = [0_u8; SYNC_ID_LEN];
        crate::getrandom::fill(&mut id).map_err(|_| Error::RandomnessUnavailable)?;
        Ok(id)
    }

    /// What this payload asks the peer to do.
    #[must_use]
    pub const fn kind(&self) -> PayloadKind {
        self.kind
    }

    /// Build a **request**: send me your full state.
    ///
    /// A request is a payload like any other: the same transport, the same authentication, and
    /// the same replay protection.
    ///
    /// A request carries **no** records (see [`PayloadKind::Request`]), so it is the
    /// fixed-length header plus a nonce and the authentication tag — [`HEADER_LEN`] +
    /// [`NONCE_LEN`] + [`TAG_LEN`] = 114 bytes plus the compressed plaintext — far smaller
    /// than any real full state.
    ///
    /// **"Small" is relative; it does not mean "always fits the smallest QR code".** The
    /// request carries the 32-byte device identifier and the 32-byte payload identifier plus
    /// the authentication tag, so it takes up a substantial part of the capacity of any QR
    /// code; the smallest versions cannot hold it. Whether it fits is answered by the
    /// **channel**: [`crate::transport::TransportCapabilities::check_fits`] can tell before
    /// sending.
    ///
    /// # Errors
    ///
    /// [`Error::RandomnessUnavailable`]: the random source is unavailable.
    pub fn request(sender: DeviceId) -> Result<Self> {
        Ok(Self {
            sync_id: Self::new_sync_id()?,
            sender,
            records: RecordSet::<Record>::new(),
            kind: PayloadKind::Request,
        })
    }

    /// Build a payload from the local vault.
    ///
    /// It seals **all** live entries and **all** tombstones. Incremental sync will be a
    /// filter parameter on this function rather than a different payload format.
    ///
    /// # When an entry and its tombstone coexist, **only** the tombstone is sent
    ///
    /// A vault can hold a live entry together with its tombstone — the state in which
    /// adjudication has not finished ([`crate::vault::Vault::record_tombstone`] never deletes
    /// the live entry). In that state the live entry must **not** be sent too: the peer would
    /// read it as "this one is not deleted yet", so every sync would trigger the same
    /// conflict on the peer and the user would face the same adjudication screen again on
    /// every sync.
    ///
    /// A tombstone represents a deletion that has **already happened**, while that live entry
    /// is local state awaiting adjudication. Broadcasting state awaiting adjudication would
    /// make every device take a decision the user has not taken yet.
    ///
    /// # The record key is derived once
    ///
    /// A payload can hold tens of thousands of records, and deriving HKDF again per record
    /// would multiply two HMAC-SHA256 computations by the number of entries. Deriving once
    /// and passing that key to every record reduces the cost from O(n) derivations to one.
    ///
    /// # Errors
    ///
    /// - [`Error::SyncTooManyRecords`]: the sum of entries and tombstones exceeds
    ///   [`MAX_RECORDS`].
    /// - [`Error::RandomnessUnavailable`]: the random source is unavailable.
    /// - Sealing failure (see [`record::seal_entry`]).
    pub fn from_vault(
        master: &MasterKey,
        sender: DeviceId,
        vault: &crate::vault::Vault,
    ) -> Result<Self> {
        let record_key = derive_record_key(master)?;
        let mut records = RecordSet::<Record>::new();
        for (id, entry) in vault.iter() {
            if vault.get_tombstone(id).is_some() {
                continue;
            }
            records.insert(record::seal_entry(&record_key, id, entry)?);
        }
        for (_, tombstone) in vault.iter_tombstones() {
            records.insert(record::seal_tombstone(&record_key, tombstone)?);
        }
        for (id, group) in vault.groups() {
            records.insert(record::seal_group(&record_key, id, group)?);
        }
        Ok(Self {
            sync_id: Self::new_sync_id()?,
            sender,
            records,
            kind: PayloadKind::Vault,
        })
    }

    /// Read a payload header without decrypting anything.
    ///
    /// Replay protection takes effect **before the vault is touched**, and the accounting needs
    /// the `sync_id`, which lives in the plaintext header. `peek` answers "have I seen this
    /// identifier" in a single call and allocates nothing large for any input, so a **garbage**
    /// payload (tampered ciphertext, or plain random bytes) is rejected without a decompression
    /// attempt and without its claimed identifier having been recorded.
    ///
    /// # It authenticates **nothing**
    ///
    /// Every returned field comes from the plaintext header, so it is only a **claim**. The
    /// one legitimate use is looking the `sync_id` up in the replay log: a hit is rejected
    /// outright (rejecting an unauthenticated payload needs no justification), and a miss
    /// still has to go through the full [`Payload::open`].
    ///
    /// # Errors
    ///
    /// The same header checks as [`Payload::open`]: magic, version, length.
    pub fn peek(data: &[u8]) -> Result<PayloadHeader> {
        let mut reader = Reader::new(data);
        let magic = reader.take(MAGIC.len()).ok_or(Error::SyncTruncated)?;
        if magic != MAGIC {
            return Err(Error::SyncBadMagic);
        }
        let version = reader.u8_bare().ok_or(Error::SyncTruncated)?;
        check_version(version)?;
        let kind_byte = reader.u8_bare().ok_or(Error::SyncTruncated)?;
        let kind = PayloadKind::from_byte(kind_byte)
            .ok_or(Error::SyncUnknownPayloadKind { value: kind_byte })?;
        let sync_id: SyncId = reader
            .take(SYNC_ID_LEN)
            .ok_or(Error::SyncTruncated)?
            .try_into()
            .map_err(|_| Error::SyncTruncated)?;
        let sender_bytes: [u8; DEVICE_ID_LEN] = reader
            .take(DEVICE_ID_LEN)
            .ok_or(Error::SyncTruncated)?
            .try_into()
            .map_err(|_| Error::SyncTruncated)?;
        Ok(PayloadHeader {
            version,
            kind,
            sync_id,
            sender: DeviceId::from_bytes(sender_bytes),
        })
    }

    /// How many records there are (entries plus tombstones).
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether there is no record at all.
    ///
    /// An empty payload is **legal**: that is exactly what a freshly registered device with
    /// no entries yet sends when it starts a sync. It must be accepted normally (the peer
    /// learns from it that there is nothing on this side), not treated as an error — that
    /// would add a branch needing a special case on the "new device joins" path.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Pack the payload into bytes that can be carried around.
    ///
    /// The order is **serialize → compress → whole-payload AEAD**.
    ///
    /// # Errors
    ///
    /// - [`Error::SyncTooManyRecords`]: the number of records exceeds [`MAX_RECORDS`].
    /// - [`Error::SyncMalformed`]: the packed plaintext exceeds [`MAX_PLAINTEXT_LEN`].
    /// - [`Error::RandomnessUnavailable`]: the random source is unavailable.
    pub fn seal(&self, master: &MasterKey) -> Result<Vec<u8>> {
        if self.records.len() > MAX_RECORDS {
            return Err(Error::SyncTooManyRecords {
                count: self.records.len(),
                limit: MAX_RECORDS,
            });
        }

        // ── 1. Serialize ────────────────────────────────────────────────────
        let mut plaintext = Vec::new();
        #[expect(
            clippy::cast_possible_truncation,
            reason = "already compared against MAX_RECORDS above, which is far below u32::MAX"
        )]
        let count = self.records.len() as u32;
        plaintext.extend_from_slice(&count.to_be_bytes());
        for record in &self.records {
            plaintext.extend_from_slice(record.entry_id.as_bytes());
            plaintext.extend_from_slice(&record.nonce);
            let len = u32::try_from(record.ciphertext.len()).map_err(|_| Error::SyncMalformed {
                reason: "a single record ciphertext exceeds 4 GiB",
            })?;
            plaintext.extend_from_slice(&len.to_be_bytes());
            plaintext.extend_from_slice(&record.ciphertext);
        }

        if plaintext.len() > MAX_PLAINTEXT_LEN {
            return Err(Error::SyncMalformed {
                reason: "the payload plaintext exceeds the limit",
            });
        }

        // ── 2. Compress ──────────────────────────────────────────────────────
        let compressed = compress::compress(&plaintext)?;

        // ── 3. Whole-payload AEAD ─────────────────────────────────────────────────
        let key = derive_envelope_key(master)?;
        let (nonce, ciphertext) = crypto::seal_bytes(&key, &self.aad(), &compressed)?;

        let mut out = Vec::with_capacity(HEADER_LEN + NONCE_LEN + ciphertext.len());
        out.extend_from_slice(MAGIC);
        out.push(FORMAT_VERSION);
        out.push(self.kind.as_byte());
        out.extend_from_slice(&self.sync_id);
        out.extend_from_slice(self.sender.as_bytes());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Take apart bytes carried in from outside, yielding records that are **still
    /// encrypted**.
    ///
    /// # It only handles the outer layer
    ///
    /// The returned [`Record`] values are not decrypted yet; that takes a call to
    /// [`record::open`] per record. Splitting the two steps is deliberate: an outer
    /// authentication failure and one unopenable record are **different** faults (the whole
    /// payload is untrustworthy versus the payload is trustworthy but its content is broken),
    /// and callers handle them differently — the former can only be retried, the latter
    /// deserves a specific diagnosis.
    ///
    /// # Errors
    ///
    /// - [`Error::SyncBadMagic`]: not a payload of this application.
    /// - [`Error::SyncUnsupportedVersion`]: unsupported version.
    /// - [`Error::SyncTruncated`]: not enough bytes.
    /// - [`Error::SyncAuthenticationFailed`]: outer authentication failed, with **no**
    ///   distinction of cause.
    /// - [`Error::SyncEmptyPayload`] / [`Error::SyncDecompressionFailed`]: compression layer.
    /// - Other structural errors.
    ///
    /// # This function must never panic
    ///
    /// The input comes entirely from a channel an attacker controls (any device on the LAN,
    /// or any byte string). All out-of-range access is stopped by the read cursor: the end
    /// offset is computed with `checked_add` and then read through `get(range)`, so both
    /// overflow and out-of-range access return `None` instead of panicking.
    pub fn open(master: &MasterKey, data: &[u8]) -> Result<Self> {
        let header = Self::peek(data)?;
        let PayloadHeader {
            version,
            kind,
            sync_id,
            sender,
        } = header;

        let mut reader = Reader::new(data);
        let _ = reader.take(HEADER_LEN).ok_or(Error::SyncTruncated)?;
        let nonce: [u8; NONCE_LEN] = reader
            .take(NONCE_LEN)
            .ok_or(Error::SyncTruncated)?
            .try_into()
            .map_err(|_| Error::SyncTruncated)?;
        let ciphertext = reader.rest();
        if ciphertext.len() < TAG_LEN {
            return Err(Error::SyncTruncated);
        }

        let aad = header_aad(version, kind, &sync_id, &sender);
        let key = derive_envelope_key(master)?;
        let compressed = crypto::open_bytes(&key, &aad, &nonce, ciphertext)
            .map_err(|_| Error::SyncAuthenticationFailed)?;

        // ── Reverse: decompress → parse ─────────────────────────────────────────────
        let plaintext = compress::decompress(&compressed)?;
        let mut reader = Reader::new(&plaintext);
        let declared = reader.u32_bare().ok_or(Error::SyncTruncated)? as usize;

        if declared > MAX_RECORDS {
            return Err(Error::SyncTooManyRecords {
                count: declared,
                limit: MAX_RECORDS,
            });
        }

        let mut records = RecordSet::<Record>::new();
        for _ in 0..declared {
            let id_bytes: [u8; EntryId::LEN] = reader
                .take(EntryId::LEN)
                .ok_or(Error::SyncTruncated)?
                .try_into()
                .map_err(|_| Error::SyncTruncated)?;
            let nonce: [u8; NONCE_LEN] = reader
                .take(NONCE_LEN)
                .ok_or(Error::SyncTruncated)?
                .try_into()
                .map_err(|_| Error::SyncTruncated)?;
            let len = reader.u32_bare().ok_or(Error::SyncTruncated)? as usize;
            if len < TAG_LEN {
                return Err(Error::SyncMalformed {
                    reason: "the record ciphertext is shorter than the authentication tag",
                });
            }
            let ciphertext = reader.take(len).ok_or(Error::SyncTruncated)?.to_vec();
            if !records.insert(Record {
                entry_id: EntryId::from_bytes(id_bytes),
                nonce,
                ciphertext,
            }) {
                return Err(Error::SyncMalformed {
                    reason: "the payload holds two records for the same entry",
                });
            }
        }

        if !reader.is_empty() {
            return Err(Error::SyncMalformed {
                reason: "the payload plaintext holds content beyond the declared record count",
            });
        }

        Ok(Self {
            sync_id,
            sender,
            records,
            kind,
        })
    }

    /// Open every record in the payload.
    ///
    /// # One failure fails the whole payload
    ///
    /// It does not "skip what cannot be opened and take the rest": the outer layer is
    /// authenticated, so a record that does not open can only mean the producer used the
    /// wrong key (for instance two devices whose vaults come from different master keys), and
    /// **partial success** would make such a fault look like "the sync succeeded but a few
    /// entries are missing" — the hardest kind to diagnose.
    ///
    /// # Errors
    ///
    /// - [`Error::SyncAuthenticationFailed`]: one record does not open.
    /// - Other structural errors (see [`record::open`]).
    pub fn open_records(&self, master: &MasterKey) -> Result<Vec<OpenedRecord>> {
        let key = derive_record_key(master)?;
        let mut opened = Vec::with_capacity(self.records.len());
        for record in &self.records {
            opened.push(record::open(&key, record)?);
        }
        Ok(opened)
    }

    /// AAD of the outer AEAD.
    fn aad(&self) -> [u8; AAD_LEN] {
        header_aad(FORMAT_VERSION, self.kind, &self.sync_id, &self.sender)
    }
}

/// The plaintext header of a payload, **unauthenticated**.
///
/// Produced by [`Payload::peek`]. Every field comes from the plaintext header, so it is only
/// a **claim**; the one legitimate use is looking the `sync_id` up in the replay log. See
/// [`Payload::peek`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayloadHeader {
    /// Payload format version. Always equal to [`FORMAT_VERSION`] (other versions are
    /// already rejected inside `peek`).
    pub version: u8,
    /// What this payload asks the peer to do.
    pub kind: PayloadKind,
    /// Payload identifier, used to consult the replay log.
    pub sync_id: SyncId,
    /// The identity the sender **claims**.
    ///
    /// As with [`Payload::sender`], it is in the AAD and therefore trustworthy after
    /// [`Payload::open`]; at the `peek` stage it is still only a claim.
    pub sender: DeviceId,
}

/// Check whether a version number is supported.
///
/// One implementation shared by [`Payload::peek`] and [`Payload::open`]. A version 1 payload
/// is rejected here; `sync::tests::a_version_1_payload_is_rejected` pins that down.
fn check_version(version: u8) -> Result<()> {
    if version != FORMAT_VERSION {
        return Err(Error::SyncUnsupportedVersion { version });
    }
    Ok(())
}

/// A bounds-checked read cursor.
///
/// It is a **separate copy** of the type of the same name in the vault module: the two read
/// different formats with different limits, and sharing one would let a change in either
/// affect the security of the other. The price is a few dozen duplicated lines, far cheaper
/// than a cursor shared across formats that would have to satisfy both sets of constraints.
struct Reader<'a> {
    /// Bytes still to be read.
    data: &'a [u8],
    /// Position of the next byte to read.
    ///
    /// Invariant: `pos <= data.len()`. Only [`Reader::take`] advances it, and `take` does
    /// **not** advance it when the range is out of bounds.
    pos: usize,
}

impl<'a> Reader<'a> {
    /// Start reading at the beginning of a byte slice.
    const fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Take `len` bytes and advance the cursor; returns `None` and does **not** advance when
    /// the bytes are not available.
    ///
    /// Two guarantees together:
    ///
    /// 1. `checked_add` stops integer overflow in `pos + len`. A record field claiming a
    ///    length of `usize::MAX` could make naive addition wrap around to a small value and
    ///    slip past the bounds check — a classic parser vulnerability, unreachable here.
    /// 2. `get(range)` stops out-of-range access.
    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(len)?;
        let slice = self.data.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }

    /// Read one byte without any semantic check.
    ///
    /// The `_bare` suffix means "raw read": the version and kind bytes may hold any value,
    /// and the caller decides whether they are legal. It is deliberately not called `u8`,
    /// because integer type names are everywhere in this module and that would read
    /// ambiguously.
    fn u8_bare(&mut self) -> Option<u8> {
        self.take(1).map(|s| s[0])
    }

    /// Read a **big-endian** 32-bit integer.
    ///
    /// Big-endian is network byte order and is how every length field of this format is
    /// written: little-endian reads backwards in a hex dump.
    fn u32_bare(&mut self) -> Option<u32> {
        self.take(4)
            .and_then(|s| <[u8; 4]>::try_from(s).ok())
            .map(u32::from_be_bytes)
    }

    /// Take all remaining bytes and push the cursor to the end.
    ///
    /// At the end it returns an empty slice rather than `None`: the outer ciphertext has a
    /// variable length, so "zero length" is a legitimate result, left for the later "at least
    /// an authentication tag" check to reject.
    fn rest(&mut self) -> &'a [u8] {
        let rest = self.data.get(self.pos..).unwrap_or(&[]);
        self.pos = self.data.len();
        rest
    }

    /// Whether the end has been reached.
    fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }
}

/// Length of the outer AAD: magic + version + kind + sync_id + device ID.
const AAD_LEN: usize = HEADER_LEN;

/// Build the AAD of the outer AEAD.
///
/// # What it authenticates
///
/// The entire plaintext header. This is how those fields are bound without being leaked:
/// `sync_id` and `sender` both have to be authenticated — the former stops swapping a
/// payload's identifier to bypass replay protection, the latter stops presenting a payload as
/// somebody else's. `kind` has to be authenticated as well, see [`PayloadKind`].
///
/// A free function rather than a method: [`Payload::open`] builds this AAD before any
/// `Payload` value exists, since authentication comes first and only then are the records
/// inside known.
///
/// # Current version only
///
/// Unlike vault files, payloads are **not forward compatible**: a version mismatch is
/// rejected. Payloads arrive over the network and are transient — they never touch disk.
/// Being lenient towards an old file on a user's device is mandatory (it is their data),
/// whereas accepting an old-version **network input** would only add a parsing path to
/// maintain that never sees real traffic. See [`LEGACY_FORMAT_VERSION_1`].
///
/// # No need to guard against a modified version number
///
/// `version` is in the AAD, so changing it to any other value makes authentication fail, and
/// changing it to the current version changes nothing. Anything that is not the current
/// version has already returned [`Error::SyncUnsupportedVersion`] earlier.
fn header_aad(
    version: u8,
    kind: PayloadKind,
    sync_id: &SyncId,
    sender: &DeviceId,
) -> [u8; AAD_LEN] {
    debug_assert_eq!(version, FORMAT_VERSION);
    let mut aad = [0_u8; AAD_LEN];
    let mut offset = 0;
    aad[..MAGIC.len()].copy_from_slice(MAGIC);
    offset += MAGIC.len();
    aad[offset] = version;
    offset += 1;
    aad[offset] = kind.as_byte();
    offset += 1;
    aad[offset..offset + SYNC_ID_LEN].copy_from_slice(sync_id);
    offset += SYNC_ID_LEN;
    aad[offset..].copy_from_slice(sender.as_bytes());
    aad
}

/// Record kind used by inner records, shared by [`record`] and the sealing side.
pub(crate) use crate::vault::RecordKind as InnerRecordKind;

const _: () = {
    assert!(InnerRecordKind::SyncEntry.as_byte() != InnerRecordKind::Entry.as_byte());
    assert!(InnerRecordKind::SyncTombstone.as_byte() != InnerRecordKind::Tombstone.as_byte());
    assert!(InnerRecordKind::SyncGroup.as_byte() != InnerRecordKind::Group.as_byte());
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::otp::{Algorithm, Digits, OtpSecret};
    use crate::vault::{
        Entry as VaultEntry, EntryKind, RecordKind, Timestamp, Vault, master_key_to_bytes,
    };

    const _: () = assert!(LEGACY_FORMAT_VERSION_1 != FORMAT_VERSION);

    /// Build one valid entry.
    fn sample_entry(seed: u8) -> VaultEntry {
        VaultEntry::new(
            format!("entry {seed}"),
            Some("组织".into()),
            format!("user{seed}@example.com"),
            OtpSecret::from_base32("JBSWY3DPEHPK3PXP").expect("valid Base32"),
            Algorithm::Sha1,
            Digits::SIX,
            EntryKind::Totp { period: 30 },
            String::new(),
            Timestamp::from(1_700_000_000_u64),
            Timestamp::from(1_700_000_000_u64),
        )
        .expect("valid fields")
    }

    /// Build one device identifier. The sync "sender" is a [`DeviceId`], not a 16-byte
    /// `EntryId`.
    fn device(seed: u8) -> DeviceId {
        DeviceId::from_bytes([seed; DEVICE_ID_LEN])
    }

    fn a_master_key() -> MasterKey {
        MasterKey::generate().expect("OS randomness available")
    }

    /// Open a payload record by record, yielding `(identifier, is_live_entry)` per record.
    ///
    /// [`Payload::records`] is indexed by identifier and **does not distinguish kinds**: a
    /// record may be a live entry or a tombstone, and `RecordSet::get` returns `Some` for
    /// both. Whether a given live entry was sent is answered only by decrypting and looking at
    /// the kind, and the returned identifiers let a test assert which record was sent rather
    /// than merely how many were.
    /// **Group records are skipped**: they are neither entries nor tombstones, and folding them
    /// into either list would make every assertion about that list depend on how many groups the
    /// vault happens to have.
    fn opened_kinds(payload: &Payload, master: &MasterKey) -> Vec<(EntryId, bool)> {
        payload
            .open_records(master)
            .expect("opening record by record")
            .into_iter()
            .filter_map(|record| match record {
                OpenedRecord::Entry { id, .. } => Some((id, true)),
                OpenedRecord::Tombstone(tombstone) => Some((tombstone.entry_id, false)),
                OpenedRecord::Group { .. } => None,
            })
            .collect()
    }

    /// Take the output of `seal` apart and yield the **actual plaintext segment**.
    ///
    /// [`Payload::open`] hands back a `Payload` with the records still **encrypted**, so the
    /// byte layout of the wire format is invisible through the public API; faults such as "the
    /// record length constant is miscounted" show up only at the byte level. This redoes the
    /// parse following the **format documentation**, a second independent implementation
    /// alongside `Payload::open`: what it checks is the layout, not internal consistency.
    fn plaintext_of(sealed: &[u8], master: &MasterKey) -> Vec<u8> {
        let mut reader = Reader::new(sealed);
        assert_eq!(reader.take(MAGIC.len()), Some(&MAGIC[..]), "magic");
        let version = reader.u8_bare().expect("version");
        assert_eq!(version, FORMAT_VERSION, "version");
        let kind = PayloadKind::from_byte(reader.u8_bare().expect("kind")).expect("valid kind");
        let sync_id = reader.take(SYNC_ID_LEN).expect("sync_id");
        let sender = reader.take(DEVICE_ID_LEN).expect("sender");
        let nonce = reader.take(NONCE_LEN).expect("nonce");
        let ciphertext = reader.rest();
        assert!(reader.is_empty(), "extra bytes follow the ciphertext");

        let sync_id = <[u8; SYNC_ID_LEN]>::try_from(sync_id).expect("correct length");
        let sender = DeviceId::from_bytes(<[u8; DEVICE_ID_LEN]>::try_from(sender).expect("length"));
        let nonce = <[u8; NONCE_LEN]>::try_from(nonce).expect("correct length");

        let aad = header_aad(version, kind, &sync_id, &sender);
        let envelope_key = derive_envelope_key(master).expect("derivation succeeds");
        let compressed = crate::vault::crypto::open_bytes(&envelope_key, &aad, &nonce, ciphertext)
            .expect("the outer layer must open");
        compress::decompress(&compressed).expect("must decompress")
    }

    /// Read the record segment of the plaintext as bytes, yielding
    /// `(entry_id, nonce, ciphertext length)` per record.
    fn parse_record_frames(plaintext: &[u8]) -> Vec<([u8; EntryId::LEN], [u8; NONCE_LEN], usize)> {
        let mut reader = Reader::new(plaintext);
        let count = reader.u32_bare().expect("record count") as usize;
        let mut frames = Vec::with_capacity(count);
        for _ in 0..count {
            let id = reader.take(EntryId::LEN).expect("identifier");
            let nonce = reader.take(NONCE_LEN).expect("nonce");
            let len = reader.u32_bare().expect("length") as usize;
            reader.take(len).expect("ciphertext");
            frames.push((
                <[u8; EntryId::LEN]>::try_from(id).expect("length"),
                <[u8; NONCE_LEN]>::try_from(nonce).expect("length"),
                len,
            ));
        }
        assert!(reader.is_empty(), "extra bytes follow the record section");
        frames
    }

    /// **The byte layout of the wire format must agree with `encoded_len`.**
    ///
    /// This is the only test that actually reads bytes. It re-parses the sealed payload
    /// following the format documentation and reconciles the result with `encoded_len`, so
    /// the assertion rests on a second, independent implementation.
    #[test]
    fn the_plaintext_record_framing_matches_encoded_len() {
        let master = a_master_key();
        let sender = device(7);

        let mut vault = Vault::new();
        for seed in 0..3_u8 {
            vault
                .insert(sample_entry(seed))
                .expect("randomness available");
        }
        let doomed = vault.insert(sample_entry(9)).expect("randomness available");
        vault.remove(&doomed, Timestamp::from(1_700_000_100_u64));

        let payload = Payload::from_vault(&master, sender, &vault).expect("packing succeeds");
        let sealed = payload.seal(&master).expect("sealing succeeds");

        let plaintext = plaintext_of(&sealed, &master);
        let frames = parse_record_frames(&plaintext);

        assert_eq!(frames.len(), payload.len(), "record count mismatch");
        assert_eq!(
            frames.len(),
            vault.len() + vault.tombstone_count() + vault.group_count(),
            "the record count in the payload must equal entries plus tombstones plus groups"
        );

        for (id_bytes, nonce, len) in &frames {
            let id = EntryId::from_bytes(*id_bytes);
            let record = payload
                .records
                .get(&id)
                .expect("the payload must hold this record");
            assert_eq!(record.nonce, *nonce, "nonce mismatch");
            assert_eq!(record.ciphertext.len(), *len, "ciphertext length mismatch");
            assert_eq!(
                record.encoded_len(),
                EntryId::LEN + NONCE_LEN + 4 + len,
                "encoded_len does not match the actual byte count of the wire format"
            );
        }

        let expected: usize = 4
            + frames.len() * (EntryId::LEN + NONCE_LEN + 4)
            + frames.iter().map(|f| f.2).sum::<usize>();
        assert_eq!(
            plaintext.len(),
            expected,
            "the plaintext total length does not match the wire format"
        );
    }

    /// The plaintext contains **no** kind byte.
    ///
    /// The kind is written into the inner AAD only, so the number of deletions in a sync is
    /// not visible; this test pins that down so the kind is not written back into the
    /// plaintext later on.
    #[test]
    fn the_record_kind_is_not_in_the_plaintext() {
        let master = a_master_key();
        let sender = device(7);

        let mut vault = Vault::new();
        let id = vault.insert(sample_entry(1)).expect("randomness available");
        vault.remove(&id, Timestamp::from(1_700_000_100_u64));

        let payload = Payload::from_vault(&master, sender, &vault).expect("packing succeeds");
        let sealed = payload.seal(&master).expect("sealing succeeds");
        let plaintext = plaintext_of(&sealed, &master);

        // The count, then the frames back to back: a kind byte anywhere would show up as a gap
        // between the two totals.
        let frames = parse_record_frames(&plaintext);
        let expected = 4 + frames
            .iter()
            .map(|(_, _, len)| EntryId::LEN + NONCE_LEN + 4 + len)
            .sum::<usize>();
        assert_eq!(
            plaintext.len(),
            expected,
            "the plaintext must be the header plus the frames, with no kind byte anywhere"
        );
        assert_eq!(
            &plaintext[4..4 + EntryId::LEN],
            frames[0].0.as_slice(),
            "the first identifier must follow the record count immediately, with no kind byte"
        );

        assert_ne!(
            RecordKind::SyncTombstone.as_byte(),
            plaintext[3],
            "byte 4 is part of the identifier"
        );
    }

    /// The domain separation constants must stay stable: changing them makes every existing
    /// payload unopenable.
    #[test]
    fn the_domain_separation_constants_are_stable() {
        assert_eq!(&HKDF_SALT_SYNC, b"Qualia2FA sync salt v1 (records)");
        assert_eq!(HKDF_SALT_SYNC.len(), 32);
        assert_eq!(MAGIC, b"Q2FASYNC");
        assert_eq!(FORMAT_VERSION, 4);
        assert!(
            crate::vault::READABLE_VERSIONS.contains(&crate::vault::FORMAT_VERSION),
            "the version a file format declares must be in its own readable version list"
        );
    }

    /// **A version 1 payload must be rejected explicitly, not force-decoded as version 2.**
    ///
    /// Version 1 and version 2 differ by one `PayloadKind` byte in the outer layer, so a
    /// lenient parser (say, "versions up to 2 are read as the new format") would take byte 9 of
    /// a version 1 payload as the kind, shift the whole `sync_id` by one, and report an
    /// **authentication failure** — a signal pointing at a wrong key rather than at the
    /// version.
    ///
    /// Version 1 was never released, so there is no compatibility burden: rejection is the
    /// only correct behaviour.
    #[test]
    fn a_version_1_payload_is_rejected() {
        let master = a_master_key();
        let mut vault = Vault::new();
        vault.insert(sample_entry(1)).expect("randomness available");
        let payload = Payload::from_vault(&master, device(1), &vault).expect("packing succeeds");
        let sealed = payload.seal(&master).expect("sealing succeeds");

        let mut legacy = sealed.clone();
        legacy[MAGIC.len()] = LEGACY_FORMAT_VERSION_1;

        for result in [
            Payload::peek(&legacy).map(|_| ()),
            Payload::open(&master, &legacy).map(|_| ()),
        ] {
            match result {
                Err(Error::SyncUnsupportedVersion { version }) => {
                    assert_eq!(version, LEGACY_FORMAT_VERSION_1);
                }
                other => panic!("version 1 was not rejected as a version, actual {other:?}"),
            }
        }
    }

    /// **A payload written by the previous release (version 3) is refused.**
    ///
    /// Version 4 changed three shapes at once - the group plaintext, the icon node inside an
    /// entry, and the width of both plaintext length prefixes - so a version 3 peer that read
    /// one would either fail with a misleading "malformed" diagnosis or, worse, skip the icon
    /// and write that loss back into its vault. The version number is what makes the refusal
    /// clean, and it is checked before anything is decrypted.
    #[test]
    fn a_version_3_payload_is_rejected() {
        let previous_release = 3_u8;
        let master = a_master_key();
        let mut vault = Vault::new();
        vault.insert(sample_entry(1)).expect("randomness available");
        let payload = Payload::from_vault(&master, device(1), &vault).expect("packing succeeds");
        let sealed = payload.seal(&master).expect("sealing succeeds");

        let mut previous = sealed.clone();
        previous[MAGIC.len()] = previous_release;

        for result in [
            Payload::peek(&previous).map(|_| ()),
            Payload::open(&master, &previous).map(|_| ()),
        ] {
            match result {
                Err(Error::SyncUnsupportedVersion { version }) => {
                    assert_eq!(version, previous_release);
                }
                other => {
                    panic!("a version 3 payload was not rejected as a version, actual {other:?}")
                }
            }
        }
    }

    /// A **request** payload: the kind is authenticated and no records are carried.
    #[test]
    fn a_request_payload_carries_no_records_and_keeps_its_kind() {
        let master = a_master_key();
        let sender = device(3);
        let payload = Payload::request(sender).expect("building a request");

        assert_eq!(payload.kind(), PayloadKind::Request);
        assert!(payload.is_empty(), "a request must not carry records");
        assert_eq!(payload.sender, sender);

        let sealed = payload.seal(&master).expect("sealing succeeds");

        let header = Payload::peek(&sealed).expect("peek");
        assert_eq!(header.kind, PayloadKind::Request);
        assert_eq!(header.sender, sender);
        assert_eq!(header.sync_id, payload.sync_id);
        assert_eq!(header.version, FORMAT_VERSION);

        let opened = Payload::open(&master, &sealed).expect("opening the payload");
        assert_eq!(opened.kind(), PayloadKind::Request);
        assert!(opened.is_empty());
    }

    /// **The kind is authenticated by the AAD**: flipping it from "state" to "request" must
    /// break authentication.
    ///
    /// If the kind were not authenticated, a third party changing a full state into a request
    /// would make the receiver send its entire vault back — a transfer triggered by an
    /// attacker that should never have happened.
    #[test]
    fn flipping_the_payload_kind_breaks_authentication() {
        let master = a_master_key();
        let mut vault = Vault::new();
        vault.insert(sample_entry(1)).expect("randomness available");
        let payload = Payload::from_vault(&master, device(1), &vault).expect("packing succeeds");
        let sealed = payload.seal(&master).expect("sealing succeeds");

        let kind_offset = MAGIC.len() + 1;
        assert_eq!(sealed[kind_offset], PayloadKind::Vault.as_byte());

        let mut flipped = sealed.clone();
        flipped[kind_offset] = PayloadKind::Request.as_byte();

        let peeked = Payload::peek(&flipped).expect("peek only reads plaintext and must succeed");
        assert_eq!(peeked.kind, PayloadKind::Request);

        let result = Payload::open(&master, &flipped);
        assert!(
            matches!(result, Err(Error::SyncAuthenticationFailed)),
            "the payload still opened after the kind was tampered with, actual {result:?}"
        );

        assert!(Payload::open(&master, &sealed).is_ok());
    }

    /// An unknown kind byte is rejected and **not** treated as a default.
    #[test]
    fn an_unknown_payload_kind_is_rejected() {
        let master = a_master_key();
        let mut vault = Vault::new();
        vault.insert(sample_entry(1)).expect("randomness available");
        let payload = Payload::from_vault(&master, device(1), &vault).expect("packing succeeds");
        let sealed = payload.seal(&master).expect("sealing succeeds");

        for bogus in [0x00_u8, 0x03, 0x80, 0xFF] {
            let mut bad = sealed.clone();
            bad[MAGIC.len() + 1] = bogus;
            let result = Payload::peek(&bad);
            match result {
                Err(Error::SyncUnknownPayloadKind { value }) => assert_eq!(value, bogus),
                other => panic!("unknown kind {bogus:#04x} was not rejected, actual {other:?}"),
            }
        }
    }

    /// `peek` never panics on **arbitrary** bytes and does not allocate in proportion to the
    /// input.
    #[test]
    fn peek_never_panics_on_arbitrary_bytes() {
        let cases: [&[u8]; 6] = [
            b"",
            b"Q",
            b"Q2FASYNC",
            b"Q2FASYNC\x02",
            b"Q2FASYNC\x02\x01",
            b"Q2FASYNC\x09\xff",
        ];
        for case in cases {
            let _ = Payload::peek(case);
        }
        let master = a_master_key();
        let payload = Payload::request(device(1)).expect("request");
        let sealed = payload.seal(&master).expect("sealing succeeds");
        assert!(Payload::peek(&sealed).is_ok());
    }

    /// The payload header layout matches the documentation **byte for byte**.
    ///
    /// This test builds the expected prefix by hand from the documentation instead of calling
    /// any `seal` logic, so it is a second independent implementation.
    #[test]
    fn the_payload_header_is_laid_out_byte_for_byte() {
        let master = a_master_key();
        let sender = device(0xAB);
        let payload = Payload::request(sender).expect("request");
        let sealed = payload.seal(&master).expect("sealing succeeds");

        assert_eq!(&sealed[..8], b"Q2FASYNC", "magic");
        assert_eq!(sealed[8], FORMAT_VERSION, "version");
        assert_eq!(sealed[9], PayloadKind::Request.as_byte(), "kind");
        assert_eq!(&sealed[10..42], &payload.sync_id, "sync_id");
        assert_eq!(&sealed[42..74], sender.as_bytes(), "sender");

        let plaintext = plaintext_of(&sealed, &master);
        assert_eq!(
            plaintext,
            0_u32.to_be_bytes(),
            "the plaintext of an empty request must be just a zero record count"
        );
        assert!(
            sealed.len() >= HEADER_LEN + NONCE_LEN + TAG_LEN,
            "not even long enough for header + nonce + authentication tag: {} < {}",
            sealed.len(),
            HEADER_LEN + NONCE_LEN + TAG_LEN
        );
        assert_eq!(
            HEADER_LEN, 74,
            "header byte count: 8 magic + 1 version + 1 kind + 32 sync_id + 32 sender"
        );
    }

    /// The payload and vault keys must really differ.
    #[test]
    fn the_sync_and_vault_keys_are_different() {
        let master = a_master_key();
        let record = derive_record_key(&master).expect("derivation succeeds");
        let envelope = derive_envelope_key(&master).expect("derivation succeeds");
        let vault_key = crate::vault::crypto::entry_key(&master).expect("derivation succeeds");

        assert_ne!(
            record, envelope,
            "the record key collided with the envelope key"
        );
        assert_ne!(
            record, vault_key,
            "the sync record key collided with the vault entry key"
        );
        assert_ne!(
            envelope, vault_key,
            "the envelope key collided with the vault entry key"
        );
    }

    /// An empty vault can be sealed and opened, and stays empty across the round trip.
    #[test]
    fn an_empty_vault_roundtrips() {
        let master = a_master_key();
        let sender = device(1);
        let payload =
            Payload::from_vault(&master, sender, &Vault::new()).expect("packing succeeds");

        assert!(payload.is_empty(), "an empty vault must produce no records");
        assert_eq!(payload.len(), 0);

        let sealed = payload.seal(&master).expect("sealing succeeds");
        let opened = Payload::open(&master, &sealed).expect("opening the payload");
        assert!(opened.is_empty());
        assert_eq!(opened.sender, sender);
        assert_eq!(opened.sync_id, payload.sync_id);
        assert!(
            opened
                .open_records(&master)
                .expect("opening record by record")
                .is_empty(),
            "an empty payload must not open any record"
        );
    }

    /// Every payload must get a **fresh** identifier, otherwise replay protection has
    /// nothing to stand on.
    #[test]
    fn every_payload_gets_a_fresh_sync_id() {
        let master = a_master_key();
        let sender = device(1);
        let mut vault = Vault::new();
        vault.insert(sample_entry(1)).expect("randomness available");

        let first = Payload::from_vault(&master, sender, &vault).expect("packing succeeds");
        let second = Payload::from_vault(&master, sender, &vault).expect("packing succeeds");
        assert_ne!(
            first.sync_id, second.sync_id,
            "two packings produced the same payload identifier"
        );
        assert_eq!(
            first.len(),
            second.len(),
            "two packings must yield the same record count"
        );
    }

    /// Sealing the same vault twice must produce different ciphertext (the nonce is random
    /// every time).
    ///
    /// Identical output would mean the nonce is reused — the most severe misuse of
    /// XChaCha20-Poly1305, and one that functional tests cannot see at all (everything keeps
    /// working).
    #[test]
    fn sealing_the_same_vault_twice_produces_different_bytes() {
        let master = a_master_key();
        let sender = device(1);
        let mut vault = Vault::new();
        vault.insert(sample_entry(1)).expect("randomness available");

        let first = Payload::from_vault(&master, sender, &vault).expect("packing succeeds");
        let second = Payload::from_vault(&master, sender, &vault).expect("packing succeeds");

        let a = first.seal(&master).expect("sealing succeeds");
        let b = second.seal(&master).expect("sealing succeeds");
        assert_ne!(
            a, b,
            "two sealings produced identical bytes, the nonce was most likely reused"
        );

        let ra = plaintext_of(&a, &master);
        let rb = plaintext_of(&b, &master);
        let fa = parse_record_frames(&ra);
        let fb = parse_record_frames(&rb);
        assert_eq!(fa.len(), fb.len());
        for (x, y) in fa.iter().zip(fb.iter()) {
            assert_eq!(x.0, y.0, "same entry");
            assert_ne!(x.1, y.1, "the same record reused its nonce");
        }
    }

    /// When a live entry and its tombstone coexist in the vault, **only** the tombstone is
    /// sent.
    ///
    /// # How that state arises
    ///
    /// It is **not** produced by [`Vault::remove`]: by design that removes the entry and
    /// leaves a tombstone behind, so it never leaves "entry and tombstone side by side". The
    /// state comes from sync itself: [`crate::vault::Vault::record_tombstone`] never deletes
    /// an existing live entry with the same ID, and the caller decides the conflict
    /// resolution outcome. A device that receives a tombstone from the peer and does not
    /// adopt it automatically stays in this state until the user decides.
    ///
    /// The state is a real and common one: two devices each hold an entry with the same name
    /// and ID, one of them deletes it, and the other stays like this while the adjudication
    /// screen is up. Broadcasting the live entry would trigger the same conflict on the peer
    /// at every sync, and the user would face the same adjudication screen every time.
    #[test]
    fn an_entry_with_a_tombstone_is_not_sent() {
        let master = a_master_key();
        let sender = device(1);

        let mut vault = Vault::new();
        let kept = vault.insert(sample_entry(1)).expect("randomness available");
        let disputed = vault.insert(sample_entry(2)).expect("randomness available");

        vault.record_tombstone(crate::vault::Tombstone {
            entry_id: disputed,
            deleted_at: Timestamp::from(1_700_000_100_u64),
            deleted_by: None,
        });

        assert_eq!(
            vault.len(),
            2,
            "precondition failed: both live entries must still be there"
        );
        assert_eq!(
            vault.tombstone_count(),
            1,
            "precondition failed: a tombstone must exist"
        );
        assert!(
            vault.get(&disputed).is_some(),
            "precondition failed: `record_tombstone` must not delete a live entry"
        );

        let payload = Payload::from_vault(&master, sender, &vault).expect("packing succeeds");
        assert_eq!(
            payload.len(),
            3,
            "there must be exactly three records: the kept entry, the tombstone, and the top group"
        );
        assert!(
            payload.records.get(&kept).is_some(),
            "the kept entry must be sent"
        );

        let records = opened_kinds(&payload, &master);
        let mut entries = Vec::new();
        let mut tombstones = Vec::new();
        for (id, is_entry) in records {
            if is_entry {
                entries.push(id);
            } else {
                tombstones.push(id);
            }
        }
        assert_eq!(
            entries,
            vec![kept],
            "exactly one live entry must be sent, and it must be the kept one"
        );
        assert_eq!(
            tombstones,
            vec![disputed],
            "exactly one tombstone must be sent"
        );
        assert!(
            !entries.contains(&disputed),
            "a live entry with a tombstone was sent as an entry"
        );
    }

    /// The record count limit is checked **outside the loop**.
    ///
    /// Otherwise a payload claiming four billion records could make us allocate a container
    /// of four billion items before noticing anything is wrong. Only a structural check is
    /// possible here: build a plaintext that claims an over-limit count and confirm it is
    /// rejected rather than allocated for.
    #[test]
    fn an_absurd_record_count_is_rejected_before_allocating() {
        let master = a_master_key();
        let mut vault = Vault::new();
        vault.insert(sample_entry(1)).expect("randomness available");
        let payload = Payload::from_vault(&master, device(1), &vault).expect("packing succeeds");

        let mut plaintext = u32::MAX.to_be_bytes().to_vec();
        plaintext.extend_from_slice(&[0_u8; 64]);
        let compressed = compress::compress(&plaintext).expect("compression succeeds");

        let envelope_key = derive_envelope_key(&master).expect("derivation succeeds");
        let aad = header_aad(
            FORMAT_VERSION,
            PayloadKind::Vault,
            &payload.sync_id,
            &payload.sender,
        );
        let (nonce, ciphertext) =
            crate::vault::crypto::seal_bytes(&envelope_key, &aad, &compressed)
                .expect("sealing succeeds");

        let mut sealed = Vec::new();
        sealed.extend_from_slice(MAGIC);
        sealed.push(FORMAT_VERSION);
        sealed.push(PayloadKind::Vault.as_byte());
        sealed.extend_from_slice(&payload.sync_id);
        sealed.extend_from_slice(payload.sender.as_bytes());
        sealed.extend_from_slice(&nonce);
        sealed.extend_from_slice(&ciphertext);

        let result = Payload::open(&master, &sealed);
        assert!(
            matches!(result, Err(Error::SyncTooManyRecords { .. })),
            "an over-limit record count was not rejected, actual {result:?}"
        );
    }

    /// The master key bytes come from the public API instead of being assembled by the test.
    #[test]
    fn the_master_key_roundtrips_through_bytes() {
        let master = a_master_key();
        let copy = MasterKey::from_bytes(master_key_to_bytes(&master)).expect("correct length");
        assert_eq!(
            derive_record_key(&master).expect("derivation succeeds"),
            derive_record_key(&copy).expect("derivation succeeds"),
            "a copy of the same master key must derive the same record key"
        );
    }
}
