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

//! Encrypted vault: on-disk format, entry encryption and decryption, atomic writes.
//!
//! # Threat model
//!
//! The vault file is assumed to be **fully readable and writable by an attacker**.
//! It travels through a cloud drive the user picked, QR codes and another device,
//! none of which this application controls. Therefore:
//!
//! - Apart from [`EntryId`] and [`GroupId`], the file holds **no plaintext semantics**. Not even
//!   "TOTP or HOTP" is visible, because that lives inside the ciphertext. Group identifiers are
//!   plaintext for the same reason entry identifiers are: they carry no meaning and two devices
//!   and the user interface need a name for the same group.
//! - Flipping any byte must make decryption fail instead of quietly yielding
//!   tampered data.
//! - All an attacker can observe is how many entries exist and how long each
//!   ciphertext is.
//!
//! **Length itself still leaks information** (how long a note or an account name
//! is). Hiding it would take padding to fixed-size blocks at several times the file
//! size. That is not done today: a known, deliberate trade-off.
//!
//! # File format v4
//!
//! All integers are **big-endian**. Layout:
//!
//! ```text
//! Offset    Length  Content
//! 0         8       magic "Q2FAVLT\0"
//! 8         1       format version (currently 4)
//! 9         1       reserved byte (must be 0; a non-zero value is rejected so a
//!                   future extension cannot be misread as an old file)
//! 10        4       record count (big-endian u32)
//! 14        ...     records, packed back to back
//! end       32      master key check value
//! ```
//!
//! Each record:
//!
//! ```text
//! Offset    Length  Content
//! 0         1       record kind (1 = live entry, 2 = tombstone, 3 = group)
//! 1         16      entry or group ID
//! 17        24      XChaCha20-Poly1305 nonce
//! 41        4       ciphertext length (big-endian u32)
//! 45        N       ciphertext (including the 16-byte authentication tag)
//! ```
//!
//! **Records are not padded**, and no checksum sits between them: the AEAD tag
//! already covers whether a record is complete, whether it belongs at this position
//! and whether it belongs to this version, so another checksum would only add
//! failure modes. The final 32 bytes are not a checksum either: they are the master
//! key check value, answering "was this file written with this key", while a record
//! tag answers "was this record modified".
//!
//! The additional authenticated data (AAD) of a record is 18 bytes: the record kind
//! (1 byte), the entry ID (16 bytes) and the format version (1 byte). The tag covers
//! those bytes together with the ciphertext.
//!
//! ## Versions 1 to 3 remain readable
//!
//! Version 1 has no trailing 32 bytes; parsing simply skips the check-value step,
//! everything else is identical. Version 2 adds that check value and is otherwise the
//! same layout. Version 3 adds the entry-kind node and the two PIN nodes. Reading is
//! driven by the version the file declares, so all three keep working unchanged: after
//! upgrading the application, an existing file must still open.
//!
//! **The converse does not hold.** A version 1 parser rejects a version 2 (or later) file,
//! because it carries a "reject any trailing bytes" check and those 32 bytes look
//! like trailing content to it. Repairing that would mean relaxing the check, which
//! would also make "the file had content appended" disappear silently - a higher
//! price than "an old version cannot open a new file". Users on the old version see
//! a clear error, not garbled data.
//!
//! ## What version 4 is for
//!
//! Two things the earlier layout could not express:
//!
//! - **The group tree.** A version 3 group record carries a flat position among the named
//!   groups and an ordered list of entries; there is no way to say "this group is inside that
//!   one", and no way to mix entries and child groups in one order. Version 4 replaces those
//!   two nodes with one list of children (see below). A version 3 parser reading a version 4
//!   group finds neither of the nodes it needs and reports a malformed record, which is the
//!   honest outcome: it has no place to put the nesting.
//! - **The icon.** An entry may now carry one picture node. A version 3 parser would skip it
//!   by its length and the entry would otherwise read normally - the icon would disappear
//!   silently, and the next write would drop it from the file. Refusing the file is what keeps
//!   "what the user sees" and "what is stored" from drifting apart.
//!
//! Mixed-version use is therefore refused in both directions; the release notes say so and
//! the error is a version error, not a decryption failure.
//!
//! # Group records are ordered child lists
//!
//! A group is a **record of its own** (kind 3) holding a name and the ordered list of its
//! children. The list *is* the order, and the parent of a child is "the group whose list names
//! it" - there is no parent field, so there is no second copy of the tree to disagree with the
//! first. The entries that belong to no named group are the **top group**, which is a group
//! like any other with the reserved identifier [`GroupId::TOP`]; it is the root of the tree.
//! A file written before groups existed still reads as a definite order: every entry in the top
//! group, in the order its record appears.
//!
//! # What synchronization does with groups
//!
//! Payloads carry group records as well, and the merge takes the union of the **group set** the
//! same way it takes the union of entries: a group only the peer has is added, and a group both
//! sides have is compared. They disagree when their names differ or when the **relative order
//! of the children they both list** differs, and that disagreement is handed to the user, who
//! picks one whole arrangement (see the `sync::merge` module).
//!
//! Two things are **not** transported, and the interface must not present them as agreed:
//!
//! - **Deleting a group.** A group removed on one device is still in the peer's payload, so the
//!   union brings it back. Entries are never lost by this - they return to the parent of the
//!   deleted group - but the group reappears.
//! - **The placement of children only one side had.** Each device keeps its own arrangement of
//!   the children the other never saw, which is the price of not turning every first sync into
//!   a conflict to adjudicate.
//!
//! # Where the key comes from
//!
//! The file **does not contain** the master key, but it **does contain a value
//! derived from it** (format version 2 onward, see [`crypto::key_check`]). That
//! value answers only "is this the key you guessed"; it cannot be inverted to the
//! master key. What it blocks is a real failure mode: a mis-stored master key going
//! unnoticed because the vault happened to be empty.
//!
//! The master key is held in the platform hardware keystore (Windows TPM).
//! **Losing the master key means the data can never be decrypted** - the unavoidable
//! price of having no server and no account password.

mod codec;
pub(crate) mod crypto;
mod entry;
mod group;

pub use crypto::{
    KEY_CHECK_LEN, MASTER_KEY_LEN, MasterKey, NONCE_LEN, TAG_LEN, key_check, master_key_to_bytes,
    verify_key_check,
};
pub use entry::{Entry, EntryIcon, EntryId, EntryKind, IconMime, Timestamp, entry_from_parsed_uri};
pub use group::{Group, GroupChild, GroupId};

pub(crate) use crypto::RecordKind;

use std::collections::BTreeMap;
use std::path::Path;

use crate::{Error, Result, otp};
use codec::{Reader, put_bytes, put_u32};
use entry::Entry as VaultEntry;

/// File magic. 8 bytes; the trailing NUL makes it recognizable in a hex editor.
pub const MAGIC: &[u8; 8] = b"Q2FAVLT\0";

/// Format version currently written: 4.
///
/// # Version 1 → 2: the master key check value
///
/// Version 2 differs from version 1 in exactly one place: the master key check value
/// at the end of the file, which lets "which master key wrote this file" be decided
/// **before the first record is read**. In version 1 the master key only took part in
/// each record AEAD, so **a file with no entries parsed successfully under any 32-byte
/// key** - a mis-stored key surfaced only once the first entry was added, long after
/// the UI had shown "opened successfully".
///
/// # Version 2 → 3: richer entry plaintext
///
/// Version 3 exists because an entry's plaintext can now carry node tags a version 2
/// parser does not know: the **entry kind** (TOTP / HOTP / mOTP / Yandex OTP / Steam
/// Guard) and the PIN fields of the two PIN-based schemes. A version 2 parser skips unknown
/// nodes by their length and then decides the type from whether a counter node is present,
/// which turns an mOTP entry into a plausible-looking TOTP entry whose code never works.
///
/// A version 3 file containing only TOTP/HOTP entries is byte-identical to a version 2 file
/// apart from this number, but the number is still written unconditionally: deciding the
/// version from the contents would make "which version is this?" a branch that itself needs
/// independent verification, and the two versions are not worth keeping compatible -
/// nothing was lost between them.
///
/// # Version 3 → 4: the group tree and the icon
///
/// A version 4 group record carries one ordered child list instead of a flat position and an
/// entry list, so the nesting and the mixed order of entries and child groups survive a round
/// trip through the file. An entry may carry an icon node. Both are shapes a version 3 parser
/// cannot represent: it finds no node it needs in the group, and it would skip the icon by its
/// length. The version number is raised so those files are refused explicitly instead of
/// losing what the user arranged.
///
/// # This constant is **also** the version number in the record AAD
///
/// It therefore cannot merely describe a layout: change the number in the AAD and
/// every old record tag stops verifying. Parsing must use **the version declared by
/// the file being parsed**, never this constant; otherwise reading a version 1 file
/// fails authentication on every record. See `version` in [`VaultFile::parse`].
///
/// # Older versions are still readable
///
/// A version 1 file has no check value, so `parse` skips that step and behaves as
/// before (including the known limitation); a version 2 file is read exactly as it was
/// written, including the check value; a version 3 file is read through the kind node. The
/// converse **does not hold**: a version 1 parser rejects any later file over the extra
/// trailing bytes (it carries a "reject any trailing bytes" check) and reports
/// [`Error::VaultTrailingBytes`] rather than an unsupported version. That follows directly
/// from version 1 having no skip path for richer future versions, and it cannot be repaired
/// without relaxing that check - which would make "the file had content appended" disappear
/// silently.
pub const FORMAT_VERSION: u8 = 4;

/// Format versions that can be parsed: 1, 2, 3 and the current [`FORMAT_VERSION`].
///
/// Listed explicitly rather than derived from [`FORMAT_VERSION`]: `&[1, FORMAT_VERSION]`
/// silently dropped version 2 the moment the constant moved to 3, which would have made every
/// existing user file unopenable with an error suggesting the file is broken.
///
/// Only added to, never removed: dropping a version would suddenly make an old file
/// unopenable, and the error message ("unsupported version") would suggest the file
/// is broken.
///
/// Public so that the "old versions stay readable" promise is pinned by tests
/// directly, instead of a test restating the version number - where both sides would
/// change together and never fail.
pub const READABLE_VERSIONS: &[u8] = &[1, 2, 3, FORMAT_VERSION];

/// Upper bound on the ciphertext length of a single record: 1 MiB.
///
/// The length comes from the file, which is attacker-controlled. Unbounded, a
/// 100-byte malicious file could claim the next record is 4 GiB and the parser would
/// try to allocate it.
///
/// 1 MiB far exceeds any real entry: even with every variable-length field at
/// [`Entry::MAX_FIELD_LEN`] (64 KiB), an entry is a few hundred KiB.
pub const MAX_RECORD_LEN: usize = 1024 * 1024;

/// Upper bound on the record count: 1,000,000.
///
/// Blocks a malicious file claiming four billion records. A million 2FA entries is
/// far beyond any real user.
pub const MAX_RECORDS: usize = 1_000_000;

/// Field tags of the plaintext entry.
///
/// Every node carries a tag and a length, so an unknown tag can be **skipped by its
/// length**. That is what lets a newer version add fields while an older version
/// still reads the fields it knows, instead of failing to parse the whole file - a
/// user does not lose access to a vault just because it was written once by a newer
/// version.
///
/// The parser must therefore handle "skip an unknown node" correctly, and a wrong
/// skip is an out-of-range read; the `vault_parse` fuzz target exercises that path.
mod tag {
    /// Display name.
    pub(super) const NAME: u8 = 0x01;
    /// Issuer.
    pub(super) const ISSUER: u8 = 0x02;
    /// Account name.
    pub(super) const ACCOUNT: u8 = 0x03;
    /// OTP secret (raw bytes, not Base32).
    pub(super) const SECRET: u8 = 0x04;
    /// HMAC algorithm.
    pub(super) const ALGORITHM: u8 = 0x05;
    /// Number of digits in a code.
    pub(super) const DIGITS: u8 = 0x06;
    /// TOTP period (seconds).
    pub(super) const PERIOD: u8 = 0x07;
    /// HOTP counter.
    pub(super) const COUNTER: u8 = 0x08;
    /// Note.
    pub(super) const NOTE: u8 = 0x09;
    /// Creation time.
    pub(super) const CREATED_AT: u8 = 0x0A;
    /// Last modification time.
    pub(super) const UPDATED_AT: u8 = 0x0B;
    /// Deletion time of a tombstone.
    pub(super) const DELETED_AT: u8 = 0x0C;
    /// Deleting device of a tombstone.
    ///
    /// Reserved for originator-side conflict adjudication; not written yet.
    pub(super) const DELETED_BY: u8 = 0x0D;
    /// Which scheme the entry uses (TOTP / HOTP / mOTP / Yandex OTP / Steam Guard).
    ///
    /// Added in format version 3. A version 1 or 2 file has no such node, and the parser then
    /// falls back to the older rule: a counter node means HOTP, its absence means TOTP.
    pub(super) const ENTRY_KIND: u8 = 0x0E;
    /// mOTP PIN (UTF-8 text).
    pub(super) const MOTP_PIN: u8 = 0x0F;
    /// Yandex OTP PIN (UTF-8 text).
    pub(super) const YANDEX_PIN: u8 = 0x10;
    /// Entry icon: one media-type byte followed by the original image bytes.
    ///
    /// Added in format version 4. It is the **entry** side of the value 0x11; the group side
    /// uses it for [`GROUP_ORDER`], which only versions 1 to 3 write.
    pub(super) const ICON: u8 = 0x11;
    /// Position of a group among the named groups (u32).
    ///
    /// Written by format versions 1 to 3 only, and read back from them. Version 4 has no flat
    /// position: a group's place is decided by the child list of its parent.
    pub(super) const GROUP_ORDER: u8 = 0x11;
    /// The ordering of a group: its entry identifiers, concatenated (16 bytes each).
    ///
    /// Written by format versions 1 to 3 only. Version 4 replaces it with [`GROUP_CHILDREN`],
    /// which can name child groups as well and lives in the same order.
    pub(super) const ENTRY_IDS: u8 = 0x12;
    /// The ordered child list of a group: one kind byte and 16 identifier bytes per child.
    ///
    /// Added in format version 4. The kind byte is [`CHILD_ENTRY`] or [`CHILD_GROUP`].
    pub(super) const GROUP_CHILDREN: u8 = 0x13;

    /// Highest tag an **entry** may carry that this version knows.
    ///
    /// Kept separate from [`tag::GROUP_TAG_MAX`] on purpose: the two record kinds are parsed by
    /// different functions, and a tag only a group record uses must stay "unknown" to the entry
    /// parser, so that a future version may repeat it there without an older build refusing the
    /// file.
    pub(super) const ENTRY_TAG_MAX: u8 = ICON;

    /// Highest tag a **group** record may carry that this version knows.
    ///
    /// Covers the three tags versions 1 to 3 write as well: reading an old file goes through the
    /// same duplicate check, and a repeated old tag is just as much a corrupt record there.
    pub(super) const GROUP_TAG_MAX: u8 = GROUP_CHILDREN;

    /// Value of the algorithm field.
    pub(super) const ALG_SHA1: u8 = 1;
    /// Value of the algorithm field.
    pub(super) const ALG_SHA256: u8 = 2;
    /// Value of the algorithm field.
    pub(super) const ALG_SHA512: u8 = 3;

    /// Value of the entry kind field: TOTP.
    pub(super) const KIND_TOTP: u8 = 1;
    /// Value of the entry kind field: HOTP.
    pub(super) const KIND_HOTP: u8 = 2;
    /// Value of the entry kind field: mOTP.
    pub(super) const KIND_MOTP: u8 = 3;
    /// Value of the entry kind field: Yandex OTP.
    pub(super) const KIND_YANDEX: u8 = 4;
    /// Value of the entry kind field: Steam Guard.
    pub(super) const KIND_STEAM: u8 = 5;

    /// Child kind byte inside [`GROUP_CHILDREN`]: an entry.
    pub(super) const CHILD_ENTRY: u8 = 0x01;
    /// Child kind byte inside [`GROUP_CHILDREN`]: a named group.
    pub(super) const CHILD_GROUP: u8 = 0x02;

    // The digit count has no constants of its own: a count from 1 to 9 is stored as the
    // byte holding that number, so [`otp::Digits::as_byte`] is the whole mapping.
}

/// A deletion record.
///
/// A deleted entry leaves a tombstone behind so that "I deleted it" becomes a fact
/// that can be synced: without one, a peer device still holding the entry looks like
/// it has a new entry and the deletion is silently undone.
///
/// # A tombstone holds no plaintext
///
/// It contains **none** of the name, account or secret of the deleted entry - only
/// the ID and timestamps, and the whole record is AEAD-encrypted like any other. An
/// attacker holding the file learns nothing about which service the user deleted.
///
/// # Retention
///
/// Tombstones **never expire**, matching the union semantics of sync: as long as one
/// device has never seen this deletion, the tombstone is useful. The cost is that the
/// file grows slowly with the number of deletions - 45 bytes of ciphertext per
/// tombstone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tombstone {
    /// ID of the deleted entry.
    pub entry_id: EntryId,
    /// Deletion time (Unix seconds).
    pub deleted_at: Timestamp,
    /// ID of the device that performed the deletion.
    ///
    /// Currently always `None`. Reserved, so that a tombstone can record which device
    /// deleted the entry.
    pub deleted_by: Option<EntryId>,
}

/// A decrypted vault.
///
/// # Ordering is deterministic
///
/// Entries and tombstones live in [`BTreeMap`]s rather than `HashMap`s, so
/// serialization is **byte-for-byte reproducible**: otherwise the same content would
/// produce different files on two devices, defeating the most obvious consistency
/// check ("are the files the same") and making round-trip comparisons in tests
/// unreliable.
#[derive(Debug, Default)]
pub struct Vault {
    /// Live entries, ordered by ID.
    entries: BTreeMap<EntryId, VaultEntry>,
    /// Tombstones, ordered by ID.
    tombstones: BTreeMap<EntryId, Tombstone>,
    /// Groups, ordered by identifier.
    ///
    /// Their **display** order is the tree walk from [`GroupId::TOP`], not the map order; see
    /// [`Vault::groups`].
    groups: BTreeMap<GroupId, Group>,
}

impl Vault {
    /// Creates an empty vault.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of live entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether there are no live entries (tombstones are not counted).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Number of tombstones.
    #[must_use]
    pub fn tombstone_count(&self) -> usize {
        self.tombstones.len()
    }

    /// Iterates the live entries by ID, in a deterministic order.
    pub fn iter(&self) -> impl Iterator<Item = (&EntryId, &VaultEntry)> {
        self.entries.iter()
    }

    /// Returns an entry by ID.
    #[must_use]
    pub fn get(&self, id: &EntryId) -> Option<&VaultEntry> {
        self.entries.get(id)
    }

    /// Returns a tombstone by ID.
    #[must_use]
    pub fn get_tombstone(&self, id: &EntryId) -> Option<&Tombstone> {
        self.tombstones.get(id)
    }

    /// Inserts an entry and returns its ID.
    ///
    /// The ID comes from a CSPRNG. Callers only display and diagnose it, they never
    /// construct one. An existing tombstone with the same ID is dropped, so "the entry
    /// exists and is marked deleted" cannot occur.
    ///
    /// # Errors
    ///
    /// Returns [`Error::RandomnessUnavailable`] when the OS random source is
    /// unavailable.
    pub fn insert(&mut self, entry: VaultEntry) -> Result<EntryId> {
        let id = EntryId::generate()?;
        self.tombstones.remove(&id);
        self.entries.insert(id, entry);
        self.top_group_mut().children.push(GroupChild::Entry(id));
        Ok(id)
    }

    /// Inserts an entry under a given ID.
    ///
    /// **For parsing an existing vault file only.** New entries go through
    /// [`Vault::insert`]; otherwise two devices generate the same ID independently and
    /// sync silently merges them into one, dropping the other.
    ///
    /// # Errors
    ///
    /// Returns [`Error::VaultDuplicateEntryId`] when the ID already has a live entry.
    /// The call is refused rather than turned into an overwrite: a duplicate ID inside
    /// a file means it was constructed or corrupted, and silently keeping one of the
    /// two would lose an entry.
    pub fn insert_with_id(&mut self, id: EntryId, entry: VaultEntry) -> Result<()> {
        if self.entries.contains_key(&id) {
            return Err(Error::VaultDuplicateEntryId);
        }
        self.entries.insert(id, entry);
        self.top_group_mut().children.push(GroupChild::Entry(id));
        Ok(())
    }

    /// Inserts an entry **without touching any ordering**.
    ///
    /// For the parser only: the group records may come after the entry records in the file, so
    /// the orderings are decided once everything has been read (see
    /// `reconcile_groups`); a membership built here would only be undone there.
    pub(crate) fn insert_parsed(&mut self, id: EntryId, entry: VaultEntry) -> Result<()> {
        if self.entries.contains_key(&id) {
            return Err(Error::VaultDuplicateEntryId);
        }
        self.entries.insert(id, entry);
        Ok(())
    }

    /// Inserts a group under a given identifier. **For parsing an existing vault file only**
    /// (the counterpart of [`Vault::insert_with_id`]).
    ///
    /// # Errors
    ///
    /// Returns [`Error::VaultDuplicateGroupId`] when the identifier is already taken.
    pub fn insert_group_with_id(&mut self, id: GroupId, group: Group) -> Result<()> {
        if self.groups.contains_key(&id) {
            return Err(Error::VaultDuplicateGroupId);
        }
        self.groups.insert(id, group);
        Ok(())
    }

    /// Replaces an **existing** entry with new content, keeping the ID and leaving
    /// **no tombstone**.
    ///
    /// The ID is the only thing two devices have to talk about "the same entry".
    /// Renaming through "delete, then insert under a new ID" would read on the peer as
    /// "one entry deleted, another added", leaving the history and the tombstones of
    /// the entry out of step: the user sees a rename turn into two entries, or the
    /// original disappear.
    ///
    /// Going through [`Vault::remove`] and then [`Vault::insert_with_id`] does not work
    /// either: `remove` leaves a tombstone **by design**, and a rename is not a
    /// deletion. A stray tombstone gets synced out and the other side may delete the
    /// entry for real because of it.
    ///
    /// # What the caller decides
    ///
    /// Whether `created_at` is preserved is up to the caller. Keeping it is the usual
    /// choice: it records when the user added the entry, and changing it on a rename
    /// makes the UI reorder.
    ///
    /// # Errors
    ///
    /// Returns [`Error::VaultEntryNotFound`] when no live entry has this ID. The call is
    /// refused rather than degraded into an insert: the caller believes it is editing an
    /// existing entry (the user pressed save in the editor) while the entry is already
    /// gone (deleted on the other side), and the useful response is to ask the user to
    /// refresh, not to add it back out of nowhere.
    pub fn replace(&mut self, id: EntryId, entry: VaultEntry) -> Result<()> {
        if !self.entries.contains_key(&id) {
            return Err(Error::VaultEntryNotFound);
        }
        self.entries.insert(id, entry);
        Ok(())
    }

    /// Deletes an entry and leaves a tombstone.
    ///
    /// Returns the removed entry when it existed, so the caller can offer undo. `now`
    /// comes from the caller (this library reads no clock).
    ///
    /// An existing tombstone for the ID keeps its original timestamp: a repeated
    /// deletion must not refresh the deletion time, or one device deleting over and over
    /// would look newer than the choice of the other device.
    ///
    /// The removed entry is handed back rather than dropped because handling the
    /// plaintext of its `OtpSecret` belongs to the caller - usually the undo prompt in
    /// the UI. This library neither decides for it nor keeps it in memory any longer.
    pub fn remove(&mut self, id: &EntryId, now: Timestamp) -> Option<VaultEntry> {
        let removed = self.entries.remove(id)?;
        self.detach_everywhere(id);
        self.tombstones.entry(*id).or_insert_with(|| Tombstone {
            entry_id: *id,
            deleted_at: now,
            deleted_by: None,
        });
        Some(removed)
    }

    /// Records a tombstone without checking for a matching live entry.
    ///
    /// Used by sync: when the peer sends a tombstone, this device may never have had
    /// that entry.
    ///
    /// # Semantics
    ///
    /// A live entry with the same ID is **not** deleted; the caller decides which side
    /// wins. This function only records the tombstone.
    pub fn record_tombstone(&mut self, tombstone: Tombstone) {
        self.tombstones.insert(tombstone.entry_id, tombstone);
    }

    /// Iterates over every tombstone.
    pub fn iter_tombstones(&self) -> impl Iterator<Item = (&EntryId, &Tombstone)> {
        self.tombstones.iter()
    }

    /// Drops a tombstone, so this ID is no longer marked as deleted.
    ///
    /// Returns the tombstone that was dropped, or `None` when this ID had none.
    ///
    /// # What it is for
    ///
    /// A tombstone records a deletion that **has happened**. Dropping it overrules that
    /// deletion: the ID becomes unknown again, and an entry arriving under it later is
    /// taken as content this device does not have rather than as something a device failed
    /// to delete.
    ///
    /// Only a user may overrule a deletion. The case it exists for is an entry this device
    /// deleted while a peer still held a copy: the peer's record arrives, the user is asked,
    /// and "the entry should not have been deleted" is answered by putting the entry back.
    /// A library deciding this on its own would be undoing an explicit user action.
    ///
    /// # A live entry with the same ID is not touched
    ///
    /// The two states mean different things: a tombstone on its own is "deleted", while a
    /// tombstone next to a live entry is "the deletion has not been adjudicated yet" (see
    /// [`crate::sync`]). Deleting the live entry is [`Vault::remove`], and neither is a side
    /// effect of the other.
    pub fn forget_tombstone(&mut self, id: &EntryId) -> Option<Tombstone> {
        self.tombstones.remove(id)
    }
}

/// The group tree.
///
/// # The membership invariant
///
/// **A live entry, and a named group, appear in at most one child list of one group.** Two lists
/// naming the same child would put it in two places at once, and the interface would have to pick
/// one anyway; this type keeps the choice here, where it can be tested, instead of leaving it to
/// each caller. [`Vault::set_children`], [`Vault::set_ordering`] and [`Vault::assign_to_group`]
/// therefore *move* a child rather than copy it, and the parser repairs a file that violates the
/// rule when it reads a file.
///
/// # Every entry is somewhere
///
/// An entry that belongs to no named group sits in the **top group**, which is why
/// [`Vault::insert`] appends it there. "In no group at all" is not a state: it would make the
/// interface silently omit entries that exist.
///
/// # The tree is the lists
///
/// There is no parent field, and no "position" number on a group: a group's place is where its
/// parent's list names it. The invariant that follows is checked where the lists are written and
/// repaired where they are read, so every method below may assume it.
impl Vault {
    /// The deepest a named group may be nested, the top group being depth zero.
    ///
    /// The user interface indents one level per step and has room for three; a deeper group has
    /// nowhere to be drawn. The limit applies when a list is written and is repaired when an
    /// older or foreign file nests deeper.
    pub const MAX_GROUP_DEPTH: usize = 3;

    /// Iterates the groups in **pre-order**: the top group first, then each group's children
    /// depth-first, in the order the lists hold them.
    ///
    /// This is the order the interface draws and the file writes. A group the walk does not
    /// reach - only possible for a vault assembled through [`Vault::insert_group_with_id`]
    /// without a parent - is appended after the walk in identifier order, so that the iterator
    /// covers every group exactly once.
    pub fn groups(&self) -> impl Iterator<Item = (&GroupId, &Group)> {
        let mut ordered: Vec<(&GroupId, &Group)> = Vec::with_capacity(self.groups.len());
        let mut visited: Vec<GroupId> = Vec::with_capacity(self.groups.len());
        self.walk_pre_order(core::iter::once(GroupId::TOP), &mut visited, &mut ordered);
        if visited.len() < self.groups.len() {
            let mut remaining: Vec<GroupId> = self
                .groups
                .keys()
                .filter(|id| !visited.contains(id))
                .copied()
                .collect();
            remaining.sort_unstable();
            self.walk_pre_order(remaining, &mut visited, &mut ordered);
        }
        ordered.into_iter()
    }

    /// Appends the pre-order walk of `roots` to `out`, adding each group at most once.
    ///
    /// An explicit stack rather than recursion: the input may be a file whose lists name a
    /// million groups, and a recursive walk would put that depth on the call stack.
    fn walk_pre_order<'a>(
        &'a self,
        roots: impl IntoIterator<Item = GroupId>,
        visited: &mut Vec<GroupId>,
        out: &mut Vec<(&'a GroupId, &'a Group)>,
    ) {
        let mut stack: Vec<GroupId> = roots.into_iter().collect();
        stack.reverse();
        while let Some(id) = stack.pop() {
            if visited.contains(&id) {
                continue;
            }
            let Some((key, group)) = self.groups.get_key_value(&id) else {
                continue;
            };
            visited.push(id);
            out.push((key, group));
            for child in group.children.iter().rev() {
                if let GroupChild::Group(child_id) = child {
                    stack.push(*child_id);
                }
            }
        }
    }

    /// Number of groups, the top group included when it exists.
    #[must_use]
    pub fn group_count(&self) -> usize {
        self.groups.len()
    }

    /// Returns a group by identifier.
    #[must_use]
    pub fn group(&self, id: &GroupId) -> Option<&Group> {
        self.groups.get(id)
    }

    /// Returns a mutable reference to a group.
    ///
    /// Used by conflict adjudication, which writes a **whole** group at once: the user chose one
    /// of two arrangements, so replacing the value is the operation, not editing its parts.
    /// Everything else goes through [`Vault::set_children`], which keeps the tree consistent.
    #[must_use]
    pub fn group_mut(&mut self, id: &GroupId) -> Option<&mut Group> {
        self.groups.get_mut(id)
    }

    /// The ordered child list of a group, or `None` when there is no such group.
    #[must_use]
    pub fn children_of(&self, id: &GroupId) -> Option<&[GroupChild]> {
        self.groups.get(id).map(|group| group.children.as_slice())
    }

    /// The parent of a named group, worked out from the child lists.
    ///
    /// `None` for the top group (it is the root) and for a group no list names. The second case
    /// is not a state a vault built through this API can be in; it exists for a value assembled
    /// by [`Vault::insert_group_with_id`].
    #[must_use]
    pub fn parent_of(&self, id: &GroupId) -> Option<GroupId> {
        if id.is_top() {
            return None;
        }
        self.groups
            .iter()
            .find(|(_, group)| group.children.contains(&GroupChild::Group(*id)))
            .map(|(parent, _)| *parent)
    }

    /// Depth of a group: the top group is 0, its named children 1, and so on.
    ///
    /// `None` when the group does not exist or no chain of parents reaches the top group (a
    /// cycle or a detached group).
    #[must_use]
    pub fn depth_of(&self, id: &GroupId) -> Option<usize> {
        if !self.groups.contains_key(id) {
            return None;
        }
        if id.is_top() {
            return Some(0);
        }
        let mut depth = 0;
        let mut current = *id;
        let mut seen: Vec<GroupId> = Vec::new();
        loop {
            if seen.contains(&current) {
                return None;
            }
            seen.push(current);
            let parent = self.parent_of(&current)?;
            depth += 1;
            if parent.is_top() {
                return Some(depth);
            }
            current = parent;
        }
    }

    /// Returns the top group, when the vault has one.
    ///
    /// An empty vault has none: the group is created by the first insertion or by parsing a
    /// file that holds entries.
    #[must_use]
    pub fn top_group(&self) -> Option<&Group> {
        self.groups.get(&GroupId::TOP)
    }

    /// The entry identifiers a group lists, in display order.
    ///
    /// A **view** of the child list: child groups are left out. A caller that needs the whole
    /// arrangement reads [`Vault::children_of`].
    #[must_use]
    pub fn ordering(&self, id: &GroupId) -> Option<Vec<EntryId>> {
        self.groups.get(id).map(Group::entry_ids)
    }

    /// Returns the group an entry belongs to.
    #[must_use]
    pub fn group_of(&self, entry: &EntryId) -> Option<&GroupId> {
        self.groups
            .iter()
            .find(|(_, group)| group.children.contains(&GroupChild::Entry(*entry)))
            .map(|(id, _)| id)
    }

    /// Iterates the entries of a group, in display order.
    ///
    /// Child groups are **not** walked: this is one level of the tree. The interface draws a
    /// group's own entries and then descends.
    ///
    /// Identifiers that name no live entry are skipped: a peer may hold a list that mentions an
    /// entry this device does not have (yet), and the interface must show the rest rather than
    /// nothing.
    pub fn entries_in(&self, id: &GroupId) -> impl Iterator<Item = (&EntryId, &VaultEntry)> {
        self.groups
            .get(id)
            .into_iter()
            .flat_map(|group| group.children.iter())
            .filter_map(|child| match child {
                GroupChild::Entry(entry_id) => {
                    self.entries.get(entry_id).map(|entry| (entry_id, entry))
                }
                GroupChild::Group(_) => None,
            })
    }

    /// Creates a named group under the **top group** and returns its identifier.
    ///
    /// # Errors
    ///
    /// Returns [`Error::RandomnessUnavailable`] when the OS random source is unavailable, and
    /// [`Error::FieldTooLong`] when the name is longer than [`Entry::MAX_FIELD_LEN`].
    pub fn create_group(&mut self, name: String) -> Result<GroupId> {
        self.create_group_in(&GroupId::TOP, name)
    }

    /// Creates a named group as the last child of `parent` and returns its identifier.
    ///
    /// The top group is created when it does not exist yet, so "create a group in a fresh vault"
    /// needs no special case.
    ///
    /// # Errors
    ///
    /// Returns [`Error::VaultGroupNotFound`] when `parent` does not exist,
    /// [`Error::VaultGroupDepthExceeded`] when the new group would be nested deeper than
    /// [`Vault::MAX_GROUP_DEPTH`], [`Error::RandomnessUnavailable`] when the random source is
    /// unavailable, and [`Error::FieldTooLong`] when the name is too long.
    pub fn create_group_in(&mut self, parent: &GroupId, name: String) -> Result<GroupId> {
        if parent.is_top() {
            self.top_group_mut();
        }
        let depth = self.depth_of(parent).ok_or(Error::VaultGroupNotFound)?;
        if depth + 1 > Self::MAX_GROUP_DEPTH {
            return Err(Error::VaultGroupDepthExceeded {
                limit: Self::MAX_GROUP_DEPTH,
                actual: depth + 1,
            });
        }
        let id = GroupId::generate()?;
        let group = Group::new(name, Vec::new())?;
        self.groups.insert(id, group);
        self.groups
            .get_mut(parent)
            .expect("the parent was checked above")
            .children
            .push(GroupChild::Group(id));
        Ok(id)
    }

    /// Creates a named group under the top group **with an identifier the caller supplies**.
    ///
    /// Used by the importer: a group's identifier has to be the one the export used, so that two
    /// devices importing the same file agree on which group is which. Everything else - where the
    /// group sits, and the rules on its name - is what [`Vault::create_group_in`] does.
    ///
    /// # Errors
    ///
    /// [`Error::VaultDuplicateGroupId`] when a group with that identifier already exists, and
    /// [`Error::FieldTooLong`] when the name is longer than [`Entry::MAX_FIELD_LEN`].
    pub fn create_group_with_id(&mut self, id: GroupId, name: String) -> Result<()> {
        if id.is_top() || self.groups.contains_key(&id) {
            return Err(Error::VaultDuplicateGroupId);
        }
        let group = Group::new(name, Vec::new())?;
        self.groups.insert(id, group);
        self.top_group_mut().children.push(GroupChild::Group(id));
        Ok(())
    }

    /// Renames a group.
    ///
    /// # Errors
    ///
    /// Returns [`Error::VaultTopGroupImmutable`] for the top group (it has no name to edit),
    /// [`Error::VaultGroupNotFound`] when there is no such group, and [`Error::FieldTooLong`]
    /// when the name is too long.
    pub fn rename_group(&mut self, id: &GroupId, name: String) -> Result<()> {
        if id.is_top() {
            return Err(Error::VaultTopGroupImmutable);
        }
        if name.len() > Entry::MAX_FIELD_LEN {
            return Err(Error::FieldTooLong {
                field: "group name",
                limit: Entry::MAX_FIELD_LEN,
                actual: name.len(),
            });
        }
        let group = self.groups.get_mut(id).ok_or(Error::VaultGroupNotFound)?;
        group.name = name;
        Ok(())
    }

    /// Removes a group. Its children move to the group's **parent**, keeping their relative
    /// order and their place: the parent's list holds the removed group at some index, and the
    /// children are spliced in there.
    ///
    /// They are **not** deleted: deleting entries or child groups because a grouping was removed
    /// would turn a presentation choice into data loss. A child group that is left without a
    /// parent (the removed group had none) goes to the top group.
    ///
    /// # Errors
    ///
    /// Returns [`Error::VaultTopGroupImmutable`] for the top group; `Ok(None)` when there is no
    /// such group.
    pub fn remove_group(&mut self, id: &GroupId) -> Result<Option<Group>> {
        if id.is_top() {
            return Err(Error::VaultTopGroupImmutable);
        }
        let parent = self.parent_of(id);
        let Some(removed) = self.groups.remove(id) else {
            return Ok(None);
        };

        let parent_id = match parent {
            Some(parent) if self.groups.contains_key(&parent) => parent,
            _ => {
                self.top_group_mut();
                GroupId::TOP
            }
        };
        let parent_group = self
            .groups
            .get_mut(&parent_id)
            .expect("the parent was checked above");
        let at = parent_group
            .children
            .iter()
            .position(|child| *child == GroupChild::Group(*id));
        match at {
            Some(at) => {
                parent_group.children.remove(at);
                for (offset, child) in removed.children.iter().enumerate() {
                    parent_group.children.insert(at + offset, *child);
                }
            }
            None => parent_group
                .children
                .extend(removed.children.iter().copied()),
        }
        Ok(Some(removed))
    }

    /// Replaces the whole child list of a group.
    ///
    /// This is the one write for every arrangement change the interface offers - moving an entry,
    /// moving a group, creating a child group, deleting a child - because a list is a sequence
    /// and a sequence is what the format stores. The caller works out the target list; the vault
    /// checks it and writes it in one step, so no intermediate state can be observed by a
    /// concurrent read or by an interrupted save.
    ///
    /// # What the check covers
    ///
    /// - the group must exist ([`Error::VaultGroupNotFound`]);
    /// - an entry reference must name a live entry ([`Error::VaultGroupUnknownEntry`]);
    /// - a group reference must name a group ([`Error::VaultGroupNotFound`]), must not be the
    ///   group itself, and must not be one of its ancestors ([`Error::VaultGroupCycle`]);
    /// - the list may not repeat a reference ([`Error::VaultGroupDuplicateChild`]) and must fit
    ///   the format ([`Error::VaultGroupTooManyChildren`]);
    /// - the deepest moved subtree must stay within [`Vault::MAX_GROUP_DEPTH`]
    ///   ([`Error::VaultGroupDepthExceeded`]).
    ///
    /// # What it moves
    ///
    /// A reference already listed by **another** group is moved out of that list: the membership
    /// invariant holds without the caller having to know where the child came from.
    ///
    /// Children the new list drops are not deleted: an entry goes back to the top group, and a
    /// child group moves to this group's parent. "Unlisted" is not a state anything can be in.
    pub fn set_children(&mut self, id: &GroupId, children: Vec<GroupChild>) -> Result<()> {
        if !self.groups.contains_key(id) {
            return Err(Error::VaultGroupNotFound);
        }
        for child in &children {
            match child {
                GroupChild::Entry(entry_id) => {
                    if !self.entries.contains_key(entry_id) {
                        return Err(Error::VaultGroupUnknownEntry);
                    }
                }
                GroupChild::Group(group_id) => {
                    if !self.groups.contains_key(group_id) {
                        return Err(Error::VaultGroupNotFound);
                    }
                    if self.is_within(*id, group_id) {
                        return Err(Error::VaultGroupCycle);
                    }
                }
            }
        }
        let replacement = Group::new(String::new(), children)?.children;
        self.check_depth(id, &replacement)?;

        let dropped: Vec<GroupChild> = self
            .groups
            .get(id)
            .expect("checked above")
            .children
            .iter()
            .filter(|child| !replacement.contains(child))
            .copied()
            .collect();

        for child in &replacement {
            self.detach_from_other_groups(child, id);
        }
        self.groups.get_mut(id).expect("checked above").children = replacement;

        let parent = self.parent_of(id);
        let parent_id = match parent {
            Some(parent) if self.groups.contains_key(&parent) => parent,
            _ => {
                self.top_group_mut();
                GroupId::TOP
            }
        };
        for child in dropped {
            match child {
                GroupChild::Entry(entry_id) => {
                    if self.entries.contains_key(&entry_id) && self.group_of(&entry_id).is_none() {
                        self.top_group_mut().children.push(child);
                    }
                }
                GroupChild::Group(group_id) => {
                    if self.groups.contains_key(&group_id) {
                        self.groups
                            .get_mut(&parent_id)
                            .expect("the parent was created or checked above")
                            .children
                            .push(child);
                    }
                }
            }
        }
        Ok(())
    }

    /// Whether `candidate` is `ancestor` itself or a group below it.
    fn is_within(&self, candidate: GroupId, ancestor: &GroupId) -> bool {
        let mut current = candidate;
        let mut seen: Vec<GroupId> = Vec::new();
        loop {
            if current == *ancestor {
                return true;
            }
            if seen.contains(&current) {
                return false;
            }
            seen.push(current);
            match self.parent_of(&current) {
                Some(parent) => current = parent,
                None => return false,
            }
        }
    }

    /// The height of a group's own subtree: one when it has no child groups.
    ///
    /// Bounded by a visited list, so a vault assembled through
    /// [`Vault::insert_group_with_id`] with a cycle in its lists cannot make this recurse
    /// forever.
    fn subtree_height(&self, id: &GroupId) -> usize {
        self.subtree_height_within(id, &mut Vec::new())
    }

    /// The recursive half of [`Vault::subtree_height`].
    fn subtree_height_within(&self, id: &GroupId, seen: &mut Vec<GroupId>) -> usize {
        if seen.contains(id) {
            return 0;
        }
        seen.push(*id);
        let mut height = 1;
        if let Some(group) = self.groups.get(id) {
            for child in &group.children {
                if let GroupChild::Group(child_id) = child
                    && self.groups.contains_key(child_id)
                {
                    height = height.max(1 + self.subtree_height_within(child_id, seen));
                }
            }
        }
        height
    }

    /// Refuses a child list that would nest a group deeper than [`Vault::MAX_GROUP_DEPTH`].
    fn check_depth(&self, id: &GroupId, children: &[GroupChild]) -> Result<()> {
        let depth = self.depth_of(id).ok_or(Error::VaultGroupNotFound)?;
        for child in children {
            if let GroupChild::Group(child_id) = child {
                let height = self.subtree_height(child_id);
                let deepest = depth + height;
                if deepest > Self::MAX_GROUP_DEPTH {
                    return Err(Error::VaultGroupDepthExceeded {
                        limit: Self::MAX_GROUP_DEPTH,
                        actual: deepest,
                    });
                }
            }
        }
        Ok(())
    }

    /// Replaces the **entry** children of a group, keeping the positions of its child groups.
    ///
    /// The order is what this call sets: index 0 comes first. Child groups keep the positions
    /// they had in the list; the entry sequence is written where the previous one started (or
    /// at the end, for a group that had no entry children).
    ///
    /// Kept for callers that arrange entries only - the importer, and the interface's "sort this
    /// group" action. Everything that moves a child group goes through [`Vault::set_children`].
    ///
    /// # Errors
    ///
    /// The errors of [`Vault::set_children`], plus
    /// [`Error::VaultGroupUnknownEntry`] for an identifier the vault does not hold.
    pub fn set_ordering(&mut self, id: &GroupId, entry_ids: Vec<EntryId>) -> Result<()> {
        let group = self.groups.get(id).ok_or(Error::VaultGroupNotFound)?;
        let existing = &group.children;
        let mut children: Vec<GroupChild> = Vec::with_capacity(existing.len() + entry_ids.len());
        let mut inserted = false;
        for child in existing {
            match child {
                GroupChild::Entry(_) => {
                    if !inserted {
                        children.extend(
                            entry_ids
                                .iter()
                                .map(|entry_id| GroupChild::Entry(*entry_id)),
                        );
                        inserted = true;
                    }
                }
                GroupChild::Group(_) => children.push(*child),
            }
        }
        if !inserted {
            children.extend(
                entry_ids
                    .iter()
                    .map(|entry_id| GroupChild::Entry(*entry_id)),
            );
        }
        self.set_children(id, children)
    }

    /// Moves an entry into a group, appending it to that group's child list.
    ///
    /// This is the "move to group" operation: it removes the entry from wherever it was, so the
    /// membership invariant holds without the caller having to know where the entry came from.
    ///
    /// # Errors
    ///
    /// Returns [`Error::VaultGroupNotFound`] when there is no such group and
    /// [`Error::VaultEntryNotFound`] when the vault holds no such entry.
    pub fn assign_to_group(&mut self, entry: &EntryId, group: &GroupId) -> Result<()> {
        if !self.entries.contains_key(entry) {
            return Err(Error::VaultEntryNotFound);
        }
        if !self.groups.contains_key(group) {
            return Err(Error::VaultGroupNotFound);
        }
        if self.group_of(entry) == Some(group) {
            return Ok(());
        }
        let child = GroupChild::Entry(*entry);
        self.detach_from_other_groups(&child, group);
        self.groups
            .get_mut(group)
            .expect("checked above")
            .children
            .push(child);
        Ok(())
    }

    /// Appends every live entry of `order` that no group lists to the **top group**.
    ///
    /// This is the "every entry is somewhere" rule in its one reusable form: the file parser
    /// runs it after reading the group records, and the sync merge runs it after applying a
    /// payload. An entry nothing claims is not "in no group" - it belongs to the entries that
    /// belong to no named group, which is what the top group is.
    ///
    /// The order is preserved, and entries that are already in a group (including the top one)
    /// are left alone, so running it twice changes nothing.
    pub fn adopt_unclaimed_entries(&mut self, order: &[EntryId]) {
        for entry_id in order {
            if self.entries.contains_key(entry_id) && self.group_of(entry_id).is_none() {
                self.top_group_mut()
                    .children
                    .push(GroupChild::Entry(*entry_id));
            }
        }
    }

    /// Drops every reference to an entry, so nothing points at an entry that is gone.
    fn detach_everywhere(&mut self, entry: &EntryId) {
        let child = GroupChild::Entry(*entry);
        for group in self.groups.values_mut() {
            group.children.retain(|candidate| *candidate != child);
        }
    }

    /// Drops references to a child from every group **except** `keep`.
    fn detach_from_other_groups(&mut self, child: &GroupChild, keep: &GroupId) {
        for (id, group) in &mut self.groups {
            if id == keep {
                continue;
            }
            group.children.retain(|candidate| candidate != child);
        }
    }

    /// The top group, created empty when the vault has none.
    fn top_group_mut(&mut self) -> &mut Group {
        self.groups
            .entry(GroupId::TOP)
            .or_insert_with(Group::top_empty)
    }

    /// Repairs the tree after reading records or merging a payload.
    ///
    /// The rules, in this order:
    ///
    /// 1. **A reference nothing can satisfy is dropped.** An unknown entry or group identifier
    ///    is removed from the list: a peer may hold a name this device never received, and a
    ///    hole no operation can fill is worse than a missing row.
    /// 2. **The first claim wins.** The walk starts at the top group and follows the lists in
    ///    their order; an entry or group met a second time is dropped from the later list. Two
    ///    lists naming the same child is a file that says two things at once, and something has
    ///    to win.
    /// 3. **A named group the walk did not reach goes to the top group**: no parent, a parent
    ///    that was dropped, a cycle, or a nesting past [`Vault::MAX_GROUP_DEPTH`]. Its own
    ///    subtree follows it, and anything still too deep is attached to the top as well - so
    ///    every group ends up somewhere.
    /// 4. **Every remaining live entry is appended to the top group**, in `entry_order` first
    ///    and then in identifier order. This is what makes a version 1 or 2 file - which has no
    ///    group records at all - read as "everything in the top group, in file order", and it is
    ///    the only definition of order those files have.
    ///
    /// `entry_order` is the order in which the entry records appeared in the file, and
    /// `group_order` the order in which the group records did, used to attach unreachable groups
    /// deterministically.
    pub(crate) fn rebuild_tree(&mut self, entry_order: &[EntryId], group_order: &[GroupId]) {
        let raw: BTreeMap<GroupId, Vec<GroupChild>> = self
            .groups
            .iter()
            .map(|(id, group)| (*id, group.children.clone()))
            .collect();

        let has_named = raw.keys().any(|id| !id.is_top());
        if self.entries.is_empty() && !has_named && !raw.contains_key(&GroupId::TOP) {
            // A vault with no records at all: nothing to arrange.
            return;
        }
        self.groups
            .entry(GroupId::TOP)
            .or_insert_with(Group::top_empty);

        let mut placed_groups: Vec<GroupId> = Vec::new();
        let mut placed_entries: Vec<EntryId> = Vec::new();
        let mut rebuilt: BTreeMap<GroupId, Vec<GroupChild>> = BTreeMap::new();

        let place = |vault: &Vault,
                     root: GroupId,
                     start_depth: usize,
                     placed_groups: &mut Vec<GroupId>,
                     placed_entries: &mut Vec<EntryId>,
                     rebuilt: &mut BTreeMap<GroupId, Vec<GroupChild>>| {
            let mut stack: Vec<(GroupId, usize)> = vec![(root, start_depth)];
            while let Some((group_id, depth)) = stack.pop() {
                if placed_groups.contains(&group_id) || !raw.contains_key(&group_id) {
                    continue;
                }
                placed_groups.push(group_id);
                let mut kept: Vec<GroupChild> = Vec::new();
                let mut shallow: Vec<(GroupId, usize)> = Vec::new();
                for child in raw.get(&group_id).map(Vec::as_slice).unwrap_or_default() {
                    match child {
                        GroupChild::Entry(entry_id) => {
                            if vault.entries.contains_key(entry_id)
                                && !placed_entries.contains(entry_id)
                            {
                                placed_entries.push(*entry_id);
                                kept.push(*child);
                            }
                        }
                        GroupChild::Group(child_id) => {
                            if child_id.is_top()
                                || !raw.contains_key(child_id)
                                || placed_groups.contains(child_id)
                            {
                                continue;
                            }
                            if depth + 1 > Vault::MAX_GROUP_DEPTH {
                                continue;
                            }
                            kept.push(*child);
                            shallow.push((*child_id, depth + 1));
                        }
                    }
                }
                rebuilt.insert(group_id, kept);
                // Depth-first: the last pushed is visited first, so push in reverse.
                for entry in shallow.into_iter().rev() {
                    stack.push(entry);
                }
            }
        };

        if raw.contains_key(&GroupId::TOP) {
            place(
                self,
                GroupId::TOP,
                0,
                &mut placed_groups,
                &mut placed_entries,
                &mut rebuilt,
            );
        }

        // Groups the walk did not reach: attach them to the top, in the order the file listed
        // them, then in identifier order for anything that list did not name.
        let mut candidates: Vec<GroupId> = group_order
            .iter()
            .copied()
            .filter(|id| !id.is_top() && raw.contains_key(id) && !placed_groups.contains(id))
            .collect();
        let mut rest: Vec<GroupId> = raw
            .keys()
            .copied()
            .filter(|id| !id.is_top() && !placed_groups.contains(id) && !candidates.contains(id))
            .collect();
        rest.sort_unstable();
        candidates.extend(rest);
        for group_id in candidates {
            if placed_groups.contains(&group_id) {
                continue;
            }
            rebuilt
                .entry(GroupId::TOP)
                .or_default()
                .push(GroupChild::Group(group_id));
            place(
                self,
                group_id,
                1,
                &mut placed_groups,
                &mut placed_entries,
                &mut rebuilt,
            );
        }

        let drop_unclaimed =
            |vault: &Vault,
             entries: &[EntryId],
             placed_entries: &mut Vec<EntryId>,
             rebuilt: &mut BTreeMap<GroupId, Vec<GroupChild>>| {
                for entry_id in entries {
                    if vault.entries.contains_key(entry_id) && !placed_entries.contains(entry_id) {
                        placed_entries.push(*entry_id);
                        rebuilt
                            .entry(GroupId::TOP)
                            .or_default()
                            .push(GroupChild::Entry(*entry_id));
                    }
                }
            };
        drop_unclaimed(self, entry_order, &mut placed_entries, &mut rebuilt);
        let remaining: Vec<EntryId> = self.entries.keys().copied().collect();
        drop_unclaimed(self, &remaining, &mut placed_entries, &mut rebuilt);

        for (id, group) in &mut self.groups {
            let children = rebuilt.remove(id).unwrap_or_default();
            group.children = children;
        }
    }
}

/// A vault file together with the master key that opens it.
///
/// Keeping the ciphertext and the key in separate stores (the key in the hardware
/// keystore) is deliberate, but passing them around separately invites "decrypted file
/// B with the key of file A" mistakes whose symptom is "nothing decrypts", which is
/// hard to pin down. This type makes the file and the key that opens it a single value.
///
/// # Lifetime
///
/// Opening a file decrypts every entry: a real vault holds tens to hundreds of entries,
/// and decrypting them at once costs far less than maintaining a state machine of
/// "which entries are decrypted". Consequently **all plaintext is in memory while the
/// vault is unlocked** - consistent with the convention that secret material exists
/// only as `secrecy` types, though paging and memory dumps remain known residual risks.
#[derive(Debug)]
pub struct VaultFile {
    /// Master key.
    master: MasterKey,
    /// Decrypted contents.
    vault: Vault,
}

impl VaultFile {
    /// Creates an empty vault with a fresh random master key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::RandomnessUnavailable`] when the OS random source is
    /// unavailable.
    pub fn create() -> Result<Self> {
        Ok(Self {
            master: MasterKey::generate()?,
            vault: Vault::new(),
        })
    }

    /// Opens an empty vault under the given master key.
    ///
    /// Used when the master key is already in the hardware keystore but there is no
    /// local file yet.
    #[must_use]
    pub fn with_master_key(master: MasterKey) -> Self {
        Self {
            master,
            vault: Vault::new(),
        }
    }

    /// Read-only reference to the master key.
    #[must_use]
    pub const fn master_key(&self) -> &MasterKey {
        &self.master
    }

    /// Takes ownership of the master key and splits the `VaultFile` apart.
    ///
    /// Used by the layer above to store the master key in the hardware keystore.
    #[must_use]
    pub fn into_parts(self) -> (MasterKey, Vault) {
        (self.master, self.vault)
    }

    /// Read-only reference to the contents.
    #[must_use]
    pub const fn vault(&self) -> &Vault {
        &self.vault
    }

    /// Mutable reference to the contents.
    pub const fn vault_mut(&mut self) -> &mut Vault {
        &mut self.vault
    }

    /// The master key and the contents together.
    ///
    /// # Why this entry point exists
    ///
    /// An operation that needs both at once cannot be written with [`VaultFile::master_key`]
    /// and [`VaultFile::vault_mut`]: the first borrows the whole value, so the second is
    /// refused even though the two fields are disjoint. Synchronization is exactly such an
    /// operation — the key seals and opens payloads while the contents are what gets merged —
    /// and the alternative would be copying the master key, which a caller that only wants
    /// to borrow has no reason to do.
    #[must_use]
    pub fn split_mut(&mut self) -> (&MasterKey, &mut Vault) {
        (&self.master, &mut self.vault)
    }

    /// Serializes to the file bytes.
    ///
    /// Records are written entries first, then tombstones, then groups in pre-order. The order of
    /// the entry records is the order the entries are read back in, which is what defines the top
    /// group's ordering in a file that has no group records (see [`VaultFile::parse`]); with group
    /// records present the arrangements come from the group records and the entry order no longer
    /// matters.
    ///
    /// # Errors
    ///
    /// Returns the corresponding error when an entry field exceeds what the format can
    /// represent, and [`Error::RandomnessUnavailable`] when the random source is
    /// unavailable (every record needs a fresh nonce).
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let total = self
            .vault
            .entries
            .len()
            .checked_add(self.vault.tombstones.len())
            .and_then(|total| total.checked_add(self.vault.groups.len()))
            .ok_or(Error::VaultTooManyRecords)?;
        if total > MAX_RECORDS {
            return Err(Error::VaultTooManyRecords);
        }
        #[expect(
            clippy::cast_possible_truncation,
            reason = "total was already compared against MAX_RECORDS (far below u32::MAX)"
        )]
        let count = total as u32;

        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.push(FORMAT_VERSION);
        out.push(0);
        put_u32(&mut out, count);

        for (id, entry) in &self.vault.entries {
            let plaintext = encode_entry(entry)?;
            write_record(
                &mut out,
                &self.master,
                FORMAT_VERSION,
                RecordKind::Entry,
                id.as_bytes(),
                &plaintext,
            )?;
        }
        for (id, tombstone) in &self.vault.tombstones {
            let plaintext = encode_tombstone(tombstone);
            write_record(
                &mut out,
                &self.master,
                FORMAT_VERSION,
                RecordKind::Tombstone,
                id.as_bytes(),
                &plaintext,
            )?;
        }

        for (id, group) in self.vault.groups() {
            let plaintext = encode_group(group)?;
            write_record(
                &mut out,
                &self.master,
                FORMAT_VERSION,
                RecordKind::Group,
                id.as_bytes(),
                &plaintext,
            )?;
        }

        out.extend_from_slice(&crypto::key_check(&self.master));
        Ok(out)
    }

    /// Parses from the file bytes.
    ///
    /// Each record is authenticated with the version **declared by this file**, not with
    /// [`FORMAT_VERSION`]; using the constant would fail authentication on every record
    /// of an older file and report it as a wrong key.
    ///
    /// # Errors
    ///
    /// Any structural problem (bad magic, unsupported version, a record running past the
    /// end, an over-long length) returns a structural error; **any authentication failure
    /// returns [`Error::VaultDecryptionFailed`]** without distinguishing the cause. A
    /// mismatching master key check value in a version 2 file returns it too: that is an
    /// earlier detection point for the same thing as "the first record does not decrypt".
    ///
    /// # Version 1 files remain readable
    ///
    /// Version 1 has no check value, so that step is skipped and behaviour is exactly as
    /// before. A file that exists must still open after an application upgrade.
    ///
    /// # A version 1 file still cannot tell a wrong key
    ///
    /// Not a regression: the file simply holds nothing to decide from. For authoritative
    /// confirmation of a key, use the challenge-response in the `auth` module, which does
    /// not depend on file contents.
    ///
    /// # This function must never panic
    ///
    /// Its input is a wholly attacker-controlled file. Every out-of-range access is
    /// blocked by the internal read cursor, and every length is compared against its
    /// limit before allocating. The `vault_parse` fuzz target checks this.
    pub fn parse(master: MasterKey, data: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(data);

        let magic = reader.take(MAGIC.len()).ok_or(Error::VaultTruncated)?;
        if magic != MAGIC {
            return Err(Error::VaultBadMagic);
        }

        let version = reader.u8().ok_or(Error::VaultTruncated)?;
        if !READABLE_VERSIONS.contains(&version) {
            return Err(Error::VaultUnsupportedVersion { version });
        }

        let reserved = reader.u8().ok_or(Error::VaultTruncated)?;
        if reserved != 0 {
            return Err(Error::VaultReservedByteNotZero { value: reserved });
        }

        let count = reader.u32().ok_or(Error::VaultTruncated)? as usize;
        if count > MAX_RECORDS {
            return Err(Error::VaultTooManyRecords);
        }

        let mut vault = Vault::new();
        let mut file_entry_order: Vec<EntryId> = Vec::new();
        let mut file_group_order: Vec<(GroupId, Option<u32>)> = Vec::new();
        for _ in 0..count {
            let kind_byte = reader.u8().ok_or(Error::VaultTruncated)?;
            let kind = RecordKind::from_byte(kind_byte)
                .ok_or(Error::VaultUnknownRecordKind { value: kind_byte })?;
            let id = reader.entry_id().ok_or(Error::VaultTruncated)?;
            let nonce = reader.nonce().ok_or(Error::VaultTruncated)?;
            let len = reader.u32().ok_or(Error::VaultTruncated)? as usize;
            if len > MAX_RECORD_LEN {
                return Err(Error::VaultRecordTooLong {
                    limit: MAX_RECORD_LEN,
                    actual: len,
                });
            }
            let ciphertext = reader.take(len).ok_or(Error::VaultTruncated)?;

            let plaintext =
                crypto::open(&master, kind, id.as_bytes(), version, &nonce, ciphertext)?;
            match kind {
                RecordKind::Entry => {
                    let entry = decode_entry(&plaintext)?;
                    vault.insert_parsed(id, entry)?;
                    file_entry_order.push(id);
                }
                RecordKind::Tombstone => {
                    let tombstone = decode_tombstone(id, &plaintext)?;
                    vault.record_tombstone(tombstone);
                }
                RecordKind::Group => {
                    let (group, order) = decode_group_with_order(&plaintext, version)?;
                    let group_id = GroupId::from_bytes(*id.as_bytes());
                    vault.insert_group_with_id(group_id, group)?;
                    file_group_order.push((group_id, order));
                }
                RecordKind::SyncEntry | RecordKind::SyncTombstone | RecordKind::SyncGroup => {
                    return Err(Error::VaultUnknownRecordKind { value: kind_byte });
                }
            }
        }

        // A version 1 to 3 file has a flat position instead of a tree: the groups the walk does
        // not reach are attached to the top in that position, which is what "all named groups
        // lie flat under the top" means for those files.
        if version < 4 {
            file_group_order.sort_by_key(|(id, order)| (order.is_none(), order.unwrap_or(0), *id));
        }
        let group_order: Vec<GroupId> = file_group_order.iter().map(|(id, _)| *id).collect();
        vault.rebuild_tree(&file_entry_order, &group_order);

        if version >= 2 {
            let stored = reader
                .take(crypto::KEY_CHECK_LEN)
                .ok_or(Error::VaultTruncated)?;
            crypto::verify_key_check(&master, stored)?;
        }

        if !reader.is_empty() {
            return Err(Error::VaultTrailingBytes {
                count: reader.remaining(),
            });
        }

        Ok(Self { master, vault })
    }
}

/// Appends one record to the output buffer.
///
/// `format_version` is passed in explicitly rather than read from [`FORMAT_VERSION`]: it
/// also goes into the AAD, and parsing must be able to match the version the file
/// declares.
fn write_record(
    out: &mut Vec<u8>,
    master: &MasterKey,
    format_version: u8,
    kind: RecordKind,
    record_id: &[u8; EntryId::LEN],
    plaintext: &[u8],
) -> Result<()> {
    let (nonce, ciphertext) = crypto::seal(master, kind, record_id, format_version, plaintext)?;
    out.push(kind.as_byte());
    out.extend_from_slice(record_id);
    out.extend_from_slice(&nonce);
    put_bytes(out, &ciphertext);
    Ok(())
}

/// Serializes the plaintext of an entry.
///
/// # Encoding rule: **every** node is "tag + u32 length + content"
///
/// No exceptions, not even one-byte enum values or eight-byte timestamps. Letting
/// fixed-width fields omit the length prefix would save a few bytes but force the parser
/// to keep a table of which tags carry a length - exactly where the "skip unknown nodes"
/// forward-compatibility mechanism is easiest to get wrong (where does the length of an
/// unknown tag come from?).
///
/// With the uniform format, skipping an unknown node has one path: read the tag, read the
/// u32 length, skip that many bytes.
///
/// # The step and the counter nodes are still written
///
/// [`tag::ENTRY_KIND`] says which scheme the entry uses, but the step (or the counter) keeps
/// travelling in the node it always travelled in. That is what lets a version 1 or 2 file be
/// read without a special case: its kind is recovered from exactly those nodes, and a version
/// 3 file is read through the same code path once the kind node has been seen.
pub(crate) fn encode_entry(entry: &VaultEntry) -> Result<Vec<u8>> {
    let mut out = Vec::new();

    put_node(&mut out, tag::NAME, entry.name.as_bytes());
    put_node(
        &mut out,
        tag::ISSUER,
        entry.issuer.as_deref().unwrap_or_default().as_bytes(),
    );
    put_node(&mut out, tag::ACCOUNT, entry.account.as_bytes());
    put_node(&mut out, tag::SECRET, entry.secret.expose());
    put_node(
        &mut out,
        tag::ALGORITHM,
        &[algorithm_to_byte(entry.algorithm)],
    );
    put_node(&mut out, tag::DIGITS, &[digits_to_byte(entry.digits)]);
    put_node(
        &mut out,
        tag::ENTRY_KIND,
        &[entry_kind_to_byte(&entry.kind)],
    );
    match &entry.kind {
        EntryKind::Totp { period }
        | EntryKind::Motp { period, .. }
        | EntryKind::Yandex { period, .. } => {
            put_node(&mut out, tag::PERIOD, &period.to_be_bytes());
        }
        EntryKind::Hotp { counter } => put_node(&mut out, tag::COUNTER, &counter.to_be_bytes()),
        EntryKind::Steam => {
            put_node(&mut out, tag::PERIOD, &otp::STEAM_PERIOD.to_be_bytes());
        }
    }
    if let Some(pin) = entry.kind.motp_pin() {
        put_node(&mut out, tag::MOTP_PIN, pin.expose().as_bytes());
    }
    if let Some(pin) = entry.kind.yandex_pin() {
        put_node(&mut out, tag::YANDEX_PIN, pin.expose().as_bytes());
    }
    if let Some(icon) = &entry.icon {
        if icon.bytes.len() > EntryIcon::MAX_BYTES {
            return Err(Error::FieldTooLong {
                field: "icon",
                limit: EntryIcon::MAX_BYTES,
                actual: icon.bytes.len(),
            });
        }
        let mut payload = Vec::with_capacity(1 + icon.bytes.len());
        payload.push(icon.mime.to_byte());
        payload.extend_from_slice(&icon.bytes);
        put_node(&mut out, tag::ICON, &payload);
    }
    put_node(&mut out, tag::NOTE, entry.note.as_bytes());
    put_node(&mut out, tag::CREATED_AT, &entry.created_at.to_be_bytes());
    put_node(&mut out, tag::UPDATED_AT, &entry.updated_at.to_be_bytes());

    Ok(out)
}

/// Appends one "tag + length + content" node.
fn put_node(out: &mut Vec<u8>, tag: u8, payload: &[u8]) {
    out.push(tag);
    put_bytes(out, payload);
}

/// Serializes the plaintext of a group.
///
/// Two nodes: the name (empty for the top group) and the ordered child list. Each child is one
/// kind byte and its 16-byte identifier. The list is the order - the child at index `i` is the
/// `i`-th entry - so there is nothing else to write and nothing that could disagree with the
/// list.
///
/// **[`tag::GROUP_ORDER`] and [`tag::ENTRY_IDS`] are not written.** They belong to format versions
/// 1 to 3, where the arrangement was flat; writing them here would put the same order in two
/// representations, and the two could disagree after a partial update. Reading an old file still
/// goes through them (see [`decode_group_with_order`]), but every file this build writes is
/// version 4.
///
/// # Errors
///
/// Returns [`Error::VaultGroupTooManyChildren`] when the child list does not fit in one node.
/// The check is here rather than only in [`Group::new`] because the list is public and a caller
/// may have grown it in place.
pub(crate) fn encode_group(group: &Group) -> Result<Vec<u8>> {
    if group.children.len() > Group::MAX_CHILDREN {
        return Err(Error::VaultGroupTooManyChildren {
            limit: Group::MAX_CHILDREN,
            actual: group.children.len(),
        });
    }

    let mut out = Vec::new();
    put_node(&mut out, tag::NAME, group.name.as_bytes());

    let per_child = 1 + GroupId::LEN;
    let mut children = Vec::with_capacity(group.children.len() * per_child);
    for child in &group.children {
        match child {
            GroupChild::Entry(id) => {
                children.push(tag::CHILD_ENTRY);
                children.extend_from_slice(id.as_bytes());
            }
            GroupChild::Group(id) => {
                children.push(tag::CHILD_GROUP);
                children.extend_from_slice(id.as_bytes());
            }
        }
    }
    put_node(&mut out, tag::GROUP_CHILDREN, &children);

    Ok(out)
}

/// Parses the plaintext of a group.
///
/// The shape depends on the version the file declared:
///
/// - **Version 4** carries one [`tag::GROUP_CHILDREN`] list. A group without it is
///   [`Error::VaultCorrupt`]: guessing a flat arrangement would silently rewrite what the user
///   arranged.
/// - **Versions 1 to 3** carry a [`tag::GROUP_ORDER`] and an [`tag::ENTRY_IDS`] list. They are
///   read as "the named group lies directly under the top group", which is the only shape those
///   versions had. The position travels beside the group (see [`decode_group_with_order`]) so
///   that the parser can attach the groups in the order the file meant.
///
/// A repeated known node is rejected as [`Error::VaultDuplicateField`] (see
/// [`tag::GROUP_TAG_MAX`]); unknown nodes are skipped by their length. The name is optional and
/// defaults to empty, which is what the top group has.
pub(crate) fn decode_group(data: &[u8], version: u8) -> Result<Group> {
    decode_group_with_order(data, version).map(|(group, _)| group)
}

/// Parses the plaintext of a group, also returning the flat position of a version 1 to 3 record.
///
/// The position is `None` for a version 4 record, which has no flat order: the tree decides
/// where a group sits. See [`decode_group`].
pub(crate) fn decode_group_with_order(data: &[u8], version: u8) -> Result<(Group, Option<u32>)> {
    let mut reader = Reader::new(data);
    let mut name = String::new();
    let mut group_order = None;
    let mut entry_ids = None;
    let mut children = None;
    let mut seen: u32 = 0;

    let mut guard = data.len() + 1;
    while !reader.is_empty() {
        guard = guard.checked_sub(1).ok_or(Error::VaultCorrupt)?;
        let node_tag = reader.u8().ok_or(Error::VaultTruncated)?;
        let len = reader.u32().ok_or(Error::VaultTruncated)? as usize;
        if len > Entry::MAX_FIELD_LEN {
            return Err(Error::FieldTooLong {
                field: "group node",
                limit: Entry::MAX_FIELD_LEN,
                actual: len,
            });
        }
        let payload = reader.take(len).ok_or(Error::VaultTruncated)?;

        if node_tag <= tag::GROUP_TAG_MAX {
            let bit = 1_u32 << node_tag;
            if seen & bit != 0 {
                return Err(Error::VaultDuplicateField { tag: node_tag });
            }
            seen |= bit;
        }

        match node_tag {
            tag::NAME => name = utf8(payload)?,
            tag::GROUP_ORDER => {
                let bytes: [u8; 4] = payload.try_into().map_err(|_| Error::VaultCorrupt)?;
                group_order = Some(u32::from_be_bytes(bytes));
            }
            tag::ENTRY_IDS => {
                if !payload.len().is_multiple_of(EntryId::LEN) {
                    return Err(Error::VaultCorrupt);
                }
                let mut ids = Vec::with_capacity(payload.len() / EntryId::LEN);
                for start in (0..payload.len()).step_by(EntryId::LEN) {
                    let end = start.checked_add(EntryId::LEN).ok_or(Error::VaultCorrupt)?;
                    let chunk = payload.get(start..end).ok_or(Error::VaultCorrupt)?;
                    let bytes: [u8; EntryId::LEN] =
                        chunk.try_into().map_err(|_| Error::VaultCorrupt)?;
                    ids.push(GroupChild::Entry(EntryId::from_bytes(bytes)));
                }
                entry_ids = Some(ids);
            }
            tag::GROUP_CHILDREN => {
                children = Some(decode_children(payload)?);
            }
            _ => {}
        }
    }

    if version >= 4 {
        // A version 4 record says where its children are. A missing node is not "an empty
        // group": treating it as one would silently discard the arrangement.
        let children = children.ok_or(Error::VaultCorrupt)?;
        return Ok((Group::new(name, children)?, None));
    }

    // Versions 1 to 3: the flat position and the entry ordering are both required.
    let order = group_order.ok_or(Error::VaultCorrupt)?;
    let children = entry_ids.ok_or(Error::VaultCorrupt)?;
    Ok((Group::new(name, children)?, Some(order)))
}

/// Decodes the payload of a [`tag::GROUP_CHILDREN`] node.
///
/// Every child is one kind byte and 16 identifier bytes, so a payload whose length is not a
/// multiple of 17 is corrupt. An unknown kind byte is refused rather than skipped: skipping it
/// would drop a child of the tree without saying so, and the next write would make that
/// permanent.
fn decode_children(payload: &[u8]) -> Result<Vec<GroupChild>> {
    const PER_CHILD: usize = 1 + GroupId::LEN;
    if !payload.len().is_multiple_of(PER_CHILD) {
        return Err(Error::VaultCorrupt);
    }
    let mut children = Vec::with_capacity(payload.len() / PER_CHILD);
    let mut at = 0;
    while at < payload.len() {
        let chunk = payload.get(at..at + PER_CHILD).ok_or(Error::VaultCorrupt)?;
        let id: [u8; GroupId::LEN] = chunk[1..].try_into().map_err(|_| Error::VaultCorrupt)?;
        let child = match chunk[0] {
            tag::CHILD_ENTRY => GroupChild::Entry(EntryId::from_bytes(id)),
            tag::CHILD_GROUP => GroupChild::Group(GroupId::from_bytes(id)),
            _ => return Err(Error::VaultCorrupt),
        };
        children.push(child);
        at += PER_CHILD;
    }
    Ok(children)
}

/// Serializes the plaintext of a tombstone.
///
/// Same node encoding as an entry, so unknown nodes are skipped here too.
pub(crate) fn encode_tombstone(tombstone: &Tombstone) -> Vec<u8> {
    let mut out = Vec::new();
    put_node(
        &mut out,
        tag::DELETED_AT,
        &tombstone.deleted_at.to_be_bytes(),
    );
    if let Some(by) = &tombstone.deleted_by {
        put_node(&mut out, tag::DELETED_BY, by.as_bytes());
    }
    out
}

/// Fields accumulated while parsing an entry's plaintext: each is filled in through an
/// `Option`, and the required ones are checked at the end.
///
/// A module-level type rather than one local to [`decode_entry`] because
/// [`assemble_entry_kind`], which turns the collected nodes into an [`EntryKind`], needs to see
/// them.
#[derive(Default)]
struct Fields {
    /// Display name.
    name: Option<String>,
    /// Issuer; an empty node is normalized to `None`.
    issuer: Option<String>,
    /// Account name.
    account: Option<String>,
    /// Secret.
    secret: Option<Vec<u8>>,
    /// Algorithm.
    algorithm: Option<otp::Algorithm>,
    /// Digits.
    digits: Option<otp::Digits>,
    /// Raw entry kind byte, kept as a byte until its state nodes have all been seen.
    kind: Option<u8>,
    /// Period.
    period: Option<u64>,
    /// Counter.
    counter: Option<u64>,
    /// mOTP PIN.
    motp_pin: Option<String>,
    /// Yandex OTP PIN.
    yandex_pin: Option<String>,
    /// Note.
    note: String,
    /// Creation time.
    created_at: Option<u64>,
    /// Modification time.
    updated_at: Option<u64>,
    /// Icon, when the entry carries one.
    icon: Option<EntryIcon>,
}

/// Parses the plaintext of an entry.
///
/// A node whose tag is at or below [`tag::ENTRY_TAG_MAX`] that appears twice is rejected as
/// [`Error::VaultDuplicateField`]; unknown tags are skipped by their length, and several nodes
/// sharing an unknown tag are tolerated, since a newer version may write them legitimately.
///
/// # How the entry kind is recovered
///
/// A version 3 file carries [`tag::ENTRY_KIND`] and that node decides, with the step / counter
/// and PIN nodes supplying the state it needs. A version 1 or 2 file has no such node, and the
/// older rule applies unchanged: a counter node means HOTP, its absence means TOTP. An unknown
/// kind byte is [`Error::VaultCorrupt`] rather than a guess — a guess would produce codes that
/// never work.
///
/// The node loop is bounded by the input length, so a file of pure garbage cannot spin
/// it.
pub(crate) fn decode_entry(data: &[u8]) -> Result<VaultEntry> {
    let mut reader = Reader::new(data);
    let mut f = Fields::default();
    let mut seen: u32 = 0;

    let mut guard = data.len() + 1;
    while !reader.is_empty() {
        guard = guard.checked_sub(1).ok_or(Error::VaultCorrupt)?;
        let node_tag = reader.u8().ok_or(Error::VaultTruncated)?;
        let len = reader.u32().ok_or(Error::VaultTruncated)? as usize;
        if len > Entry::MAX_FIELD_LEN {
            return Err(Error::FieldTooLong {
                field: "vault node",
                limit: Entry::MAX_FIELD_LEN,
                actual: len,
            });
        }
        let payload = reader.take(len).ok_or(Error::VaultTruncated)?;

        if node_tag <= tag::ENTRY_TAG_MAX {
            let bit = 1_u32 << node_tag;
            if seen & bit != 0 {
                return Err(Error::VaultDuplicateField { tag: node_tag });
            }
            seen |= bit;
        }

        match node_tag {
            tag::NAME => f.name = Some(utf8(payload)?),
            tag::ISSUER => {
                let text = utf8(payload)?;
                f.issuer = if text.is_empty() { None } else { Some(text) };
            }
            tag::ACCOUNT => f.account = Some(utf8(payload)?),
            tag::SECRET => {
                f.secret = Some(payload.to_vec());
            }
            tag::ALGORITHM => {
                f.algorithm =
                    Some(algorithm_from_byte(single_byte(payload)?).ok_or(Error::VaultCorrupt)?);
            }
            tag::DIGITS => {
                f.digits =
                    Some(digits_from_byte(single_byte(payload)?).ok_or(Error::VaultCorrupt)?);
            }
            tag::ENTRY_KIND => {
                let byte = single_byte(payload)?;
                if entry_kind_byte_is_known(byte) {
                    f.kind = Some(byte);
                } else {
                    return Err(Error::VaultCorrupt);
                }
            }
            tag::PERIOD => f.period = Some(u64_from(payload)?),
            tag::COUNTER => f.counter = Some(u64_from(payload)?),
            tag::MOTP_PIN => f.motp_pin = Some(utf8(payload)?),
            tag::YANDEX_PIN => f.yandex_pin = Some(utf8(payload)?),
            tag::ICON => {
                let (mime_byte, bytes) = payload.split_first().ok_or(Error::VaultCorrupt)?;
                let mime = IconMime::from_byte(*mime_byte).ok_or(Error::VaultCorrupt)?;
                f.icon = Some(EntryIcon::new(mime, bytes.to_vec())?);
            }
            tag::NOTE => f.note = utf8(payload)?,
            tag::CREATED_AT => f.created_at = Some(u64_from(payload)?),
            tag::UPDATED_AT => f.updated_at = Some(u64_from(payload)?),
            _ => {}
        }
    }

    let kind = assemble_entry_kind(&mut f)?;
    let created_at = f.created_at.ok_or(Error::VaultCorrupt)?;
    let entry = Entry::new(
        f.name.ok_or(Error::VaultCorrupt)?,
        f.issuer,
        f.account.ok_or(Error::VaultCorrupt)?,
        otp::OtpSecret::from_bytes(f.secret.ok_or(Error::VaultCorrupt)?)?,
        f.algorithm.ok_or(Error::VaultCorrupt)?,
        f.digits.ok_or(Error::VaultCorrupt)?,
        kind,
        f.note,
        created_at,
        f.updated_at.unwrap_or(created_at),
    )?;
    Ok(entry.with_icon(f.icon))
}

/// Assembles the entry kind from the parsed nodes.
///
/// The three cases differ in where the scheme comes from, and all three end in the same place:
///
/// - **A kind node is present** (format version 3): it decides, and the nodes it needs must be
///   there. A PIN node on a scheme without a PIN, or a missing step, is a malformed entry.
/// - **No kind node** (format versions 1 and 2): the old rule decides — a counter node means
///   HOTP, its absence means TOTP — and a PIN node cannot appear, because those versions had
///   no such field.
fn assemble_entry_kind(f: &mut Fields) -> Result<EntryKind> {
    let pin_fields_are_empty = f.motp_pin.is_none() && f.yandex_pin.is_none();

    let Some(byte) = f.kind else {
        if !pin_fields_are_empty {
            return Err(Error::VaultCorrupt);
        }
        return match f.counter {
            Some(counter) => Ok(EntryKind::Hotp { counter }),
            None => Ok(EntryKind::Totp {
                period: f.period.ok_or(Error::VaultCorrupt)?,
            }),
        };
    };

    let pin_only_where_meaningful = |pin: &Option<String>| pin.is_some();
    match byte {
        tag::KIND_TOTP => {
            if !pin_fields_are_empty {
                return Err(Error::VaultCorrupt);
            }
            Ok(EntryKind::Totp {
                period: f.period.ok_or(Error::VaultCorrupt)?,
            })
        }
        tag::KIND_HOTP => {
            if !pin_fields_are_empty {
                return Err(Error::VaultCorrupt);
            }
            Ok(EntryKind::Hotp {
                counter: f.counter.ok_or(Error::VaultCorrupt)?,
            })
        }
        tag::KIND_MOTP => {
            if pin_only_where_meaningful(&f.yandex_pin) {
                return Err(Error::VaultCorrupt);
            }
            Ok(EntryKind::Motp {
                period: f.period.ok_or(Error::VaultCorrupt)?,
                pin: f
                    .motp_pin
                    .take()
                    .filter(|text| !text.is_empty())
                    .map(crate::motp::MotpPin::new),
            })
        }
        tag::KIND_YANDEX => {
            if pin_only_where_meaningful(&f.motp_pin) {
                return Err(Error::VaultCorrupt);
            }
            Ok(EntryKind::Yandex {
                period: f.period.ok_or(Error::VaultCorrupt)?,
                pin: f
                    .yandex_pin
                    .take()
                    .filter(|text| !text.is_empty())
                    .map(crate::yaotp::YandexPin::new),
            })
        }
        tag::KIND_STEAM => {
            if !pin_fields_are_empty {
                return Err(Error::VaultCorrupt);
            }
            Ok(EntryKind::Steam)
        }
        _ => Err(Error::VaultCorrupt),
    }
}

/// Parses the plaintext of a tombstone.
pub(crate) fn decode_tombstone(id: EntryId, data: &[u8]) -> Result<Tombstone> {
    let mut reader = Reader::new(data);
    let mut deleted_at = None;
    let mut deleted_by = None;
    let mut guard = data.len() + 1;

    while !reader.is_empty() {
        guard = guard.checked_sub(1).ok_or(Error::VaultCorrupt)?;
        let node_tag = reader.u8().ok_or(Error::VaultTruncated)?;
        let len = reader.u32().ok_or(Error::VaultTruncated)? as usize;
        if len > Entry::MAX_FIELD_LEN {
            return Err(Error::VaultCorrupt);
        }
        let payload = reader.take(len).ok_or(Error::VaultTruncated)?;
        match node_tag {
            tag::DELETED_AT => deleted_at = Some(u64_from(payload)?),
            tag::DELETED_BY => {
                let bytes: [u8; EntryId::LEN] =
                    payload.try_into().map_err(|_| Error::VaultCorrupt)?;
                deleted_by = Some(EntryId::from_bytes(bytes));
            }
            _ => {}
        }
    }

    Ok(Tombstone {
        entry_id: id,
        deleted_at: deleted_at.ok_or(Error::VaultCorrupt)?,
        deleted_by,
    })
}

/// Interprets bytes as UTF-8.
fn utf8(bytes: &[u8]) -> Result<String> {
    String::from_utf8(bytes.to_vec()).map_err(|_| Error::VaultInvalidUtf8)
}

/// Reads the single byte of a node that is exactly one byte long.
///
/// Any other length is rejected: extra bytes have no meaning, and ignoring them would let
/// an attacker smuggle data behind a known field.
fn single_byte(payload: &[u8]) -> Result<u8> {
    let bytes: [u8; 1] = payload.try_into().map_err(|_| Error::VaultCorrupt)?;
    Ok(bytes[0])
}

/// Reads a `u64` from an eight-byte node.
fn u64_from(payload: &[u8]) -> Result<u64> {
    let bytes: [u8; 8] = payload.try_into().map_err(|_| Error::VaultCorrupt)?;
    Ok(u64::from_be_bytes(bytes))
}

/// Algorithm to storage byte.
const fn algorithm_to_byte(algorithm: otp::Algorithm) -> u8 {
    match algorithm {
        otp::Algorithm::Sha1 => tag::ALG_SHA1,
        otp::Algorithm::Sha256 => tag::ALG_SHA256,
        otp::Algorithm::Sha512 => tag::ALG_SHA512,
    }
}

/// Storage byte to algorithm. An unknown value returns `None`.
///
/// There is **no** fallback to SHA-1: a silent fallback would give the user permanently
/// wrong codes with nothing to diagnose.
const fn algorithm_from_byte(byte: u8) -> Option<otp::Algorithm> {
    match byte {
        tag::ALG_SHA1 => Some(otp::Algorithm::Sha1),
        tag::ALG_SHA256 => Some(otp::Algorithm::Sha256),
        tag::ALG_SHA512 => Some(otp::Algorithm::Sha512),
        _ => None,
    }
}

/// Digit count to storage byte: the count itself.
///
/// No mapping table exists, so none can drift out of step with the type; the vault format
/// stores a count from 1 to 9 as one byte holding that number.
const fn digits_to_byte(digits: otp::Digits) -> u8 {
    digits.as_byte()
}

/// Storage byte to digit count. A byte outside 1..=9 returns `None`.
///
/// There is no fallback to six digits: a silent fallback would give the user permanently
/// wrong codes with nothing to diagnose.
fn digits_from_byte(byte: u8) -> Option<otp::Digits> {
    otp::Digits::try_from(byte).ok()
}

/// Entry kind to storage byte.
///
/// Only the **scheme** is stored here; the step, the counter and the PINs travel in nodes of
/// their own, so that a version 1 or 2 file (which has no kind node) can be reconstructed from
/// the same nodes.
const fn entry_kind_to_byte(kind: &EntryKind) -> u8 {
    match kind {
        EntryKind::Totp { .. } => tag::KIND_TOTP,
        EntryKind::Hotp { .. } => tag::KIND_HOTP,
        EntryKind::Motp { .. } => tag::KIND_MOTP,
        EntryKind::Yandex { .. } => tag::KIND_YANDEX,
        EntryKind::Steam => tag::KIND_STEAM,
    }
}

/// Whether a kind byte names a scheme this build knows.
///
/// A byte from a newer version is **rejected rather than guessed**: reading an unknown scheme
/// as TOTP would produce an entry whose codes never work, and nothing in the UI would say why.
const fn entry_kind_byte_is_known(byte: u8) -> bool {
    matches!(
        byte,
        tag::KIND_TOTP | tag::KIND_HOTP | tag::KIND_MOTP | tag::KIND_YANDEX | tag::KIND_STEAM
    )
}

/// Writes bytes to a file atomically.
///
/// "Write a file" is not one operation at the OS level: the target is truncated and then
/// written. Losing power or crashing between the two leaves a **truncated vault**, every
/// entry damaged, with no backup at all. The sequence here writes a temporary file in the
/// same directory, `sync_all`s it, then renames it over the target; `rename` is atomic on
/// POSIX and on Windows within one volume, so the target holds either the old content or
/// the new content, never something in between.
///
/// The temporary name carries the process ID, so two processes in the same directory
/// cannot overwrite the temporary file of each other.
///
/// `sync_all` rather than `flush`: `flush` only hands data from userspace buffers to the
/// kernel, and a crash can still lose the kernel page cache, leaving the renamed target
/// **empty or incomplete** - worse than a torn write, because it looks like it succeeded.
///
/// # Errors
///
/// Any I/O failure returns [`Error::VaultIo`]. A failing call deletes the temporary file
/// on a best-effort basis (a cleanup failure must not mask the real error) and leaves the
/// existing target file **untouched**: a temporary file may remain, which is cleanable
/// garbage rather than data corruption.
pub fn write_file_atomically(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut tmp_name = path.file_name().unwrap_or_default().to_os_string();
    tmp_name.push(format!(".tmp{}", std::process::id()));
    let tmp_path = parent.join(tmp_name);

    let cleanup = |err| {
        let _ = std::fs::remove_file(&tmp_path);
        err
    };

    let mut file = std::fs::File::create(&tmp_path).map_err(|e| Error::VaultIo {
        reason: e.to_string(),
    })?;
    file.write_all(data).map_err(|e| {
        cleanup(Error::VaultIo {
            reason: e.to_string(),
        })
    })?;
    file.sync_all().map_err(|e| {
        cleanup(Error::VaultIo {
            reason: e.to_string(),
        })
    })?;
    drop(file);

    std::fs::rename(&tmp_path, path).map_err(|e| {
        cleanup(Error::VaultIo {
            reason: e.to_string(),
        })
    })?;
    Ok(())
}

/// Reads and parses a vault from a file.
///
/// # Errors
///
/// A read failure returns [`Error::VaultIo`]; everything else as in
/// [`VaultFile::parse`].
pub fn read_file(master: MasterKey, path: &Path) -> Result<VaultFile> {
    let data = std::fs::read(path).map_err(|e| Error::VaultIo {
        reason: e.to_string(),
    })?;
    VaultFile::parse(master, &data)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret() -> otp::OtpSecret {
        otp::OtpSecret::from_base32("JBSWY3DPEHPK3PXP").expect("valid secret")
    }

    fn sample_entry(name: &str) -> VaultEntry {
        Entry::new(
            name.into(),
            Some("Example".into()),
            "alice".into(),
            secret(),
            otp::Algorithm::Sha256,
            otp::Digits::EIGHT,
            EntryKind::Totp { period: 30 },
            "note".into(),
            1_700_000_000,
            1_700_000_123,
        )
        .expect("valid entry")
    }

    fn sample_hotp_entry() -> VaultEntry {
        Entry::new(
            "HOTP".into(),
            None,
            "bob".into(),
            secret(),
            otp::Algorithm::Sha1,
            otp::Digits::SIX,
            EntryKind::Hotp { counter: 42 },
            String::new(),
            1_700_000_000,
            1_700_000_000,
        )
        .expect("valid entry")
    }

    /// Asserts that two entries are equal in **every** field.
    ///
    /// `OtpSecret` does not implement `PartialEq`, so the secret is compared through its
    /// Base32 representation.
    fn assert_entry_eq(a: &VaultEntry, b: &VaultEntry) {
        assert_eq!(a.name, b.name, "name");
        assert_eq!(a.issuer, b.issuer, "issuer");
        assert_eq!(a.account, b.account, "account");
        assert_eq!(a.secret.to_base32(), b.secret.to_base32(), "secret");
        assert_eq!(a.algorithm, b.algorithm, "algorithm");
        assert_eq!(a.digits, b.digits, "digits");
        assert_eq!(a.kind, b.kind, "kind");
        assert_eq!(a.note, b.note, "note");
        assert_eq!(a.created_at, b.created_at, "created_at");
        assert_eq!(a.updated_at, b.updated_at, "updated_at");
    }

    #[test]
    fn create_starts_empty() {
        let file = VaultFile::create().expect("OS randomness available");
        assert!(file.vault().is_empty());
        assert_eq!(file.vault().len(), 0);
        assert_eq!(file.vault().tombstone_count(), 0);
    }

    /// Serialize, parse and decrypt preserve every field.
    #[test]
    fn roundtrip_preserves_every_field() {
        let mut file = VaultFile::create().expect("OS randomness available");
        let id = file
            .vault_mut()
            .insert(sample_entry("GitHub"))
            .expect("insertion succeeds");

        let bytes = file.serialize().expect("serialization succeeds");
        let reopened = VaultFile::parse(
            MasterKey::from_bytes(master_key_to_bytes(file.master_key())).expect("correct length"),
            &bytes,
        )
        .expect("parsing succeeds");

        assert_eq!(reopened.vault().len(), 1);
        let restored = reopened.vault().get(&id).expect("the entry must exist");
        assert_entry_eq(&sample_entry("GitHub"), restored);
    }

    /// An HOTP entry keeps its counter.
    #[test]
    fn roundtrip_preserves_hotp_counter() {
        let mut file = VaultFile::create().expect("OS randomness available");
        let id = file
            .vault_mut()
            .insert(sample_hotp_entry())
            .expect("insertion succeeds");
        let bytes = file.serialize().expect("serialization succeeds");
        let reopened = VaultFile::parse(
            MasterKey::from_bytes(master_key_to_bytes(file.master_key())).expect("correct length"),
            &bytes,
        )
        .expect("parsing succeeds");
        let restored = reopened.vault().get(&id).expect("the entry must exist");
        assert_eq!(restored.kind, EntryKind::Hotp { counter: 42 });
        assert_eq!(
            restored.uri_type(),
            crate::uri::UriType::Hotp,
            "the restored entry is still HOTP"
        );
    }

    /// Tombstones survive a round trip and do **not** turn into live entries.
    #[test]
    fn roundtrip_preserves_tombstones() {
        let mut file = VaultFile::create().expect("OS randomness available");
        let id = file
            .vault_mut()
            .insert(sample_entry("Doomed"))
            .expect("insertion succeeds");
        file.vault_mut().remove(&id, 1_800_000_000);

        let bytes = file.serialize().expect("serialization succeeds");
        let reopened = VaultFile::parse(
            MasterKey::from_bytes(master_key_to_bytes(file.master_key())).expect("correct length"),
            &bytes,
        )
        .expect("parsing succeeds");

        assert!(
            reopened.vault().is_empty(),
            "the entry must have been deleted"
        );
        assert_eq!(reopened.vault().tombstone_count(), 1);
        let tombstone = reopened
            .vault()
            .get_tombstone(&id)
            .expect("the tombstone must exist");
        assert_eq!(tombstone.entry_id, id);
        assert_eq!(tombstone.deleted_at, 1_800_000_000);
        assert_eq!(tombstone.deleted_by, None);
    }

    /// A repeated removal does not refresh the tombstone timestamp.
    #[test]
    fn repeated_removal_keeps_original_timestamp() {
        let mut vault = Vault::new();
        let id = vault.insert(sample_entry("x")).expect("insertion succeeds");
        vault.remove(&id, 100);
        assert!(vault.remove(&id, 999).is_none());
        assert_eq!(
            vault
                .get_tombstone(&id)
                .expect("tombstone exists")
                .deleted_at,
            100
        );
    }

    /// Many entries survive a round trip, in a deterministic order.
    #[test]
    fn roundtrip_preserves_many_entries() {
        let mut file = VaultFile::create().expect("OS randomness available");
        let mut ids = Vec::new();
        for i in 0..64 {
            ids.push(
                file.vault_mut()
                    .insert(sample_entry(&format!("entry-{i}")))
                    .expect("insertion succeeds"),
            );
        }
        let bytes = file.serialize().expect("serialization succeeds");
        let reopened = VaultFile::parse(
            MasterKey::from_bytes(master_key_to_bytes(file.master_key())).expect("correct length"),
            &bytes,
        )
        .expect("parsing succeeds");
        assert_eq!(reopened.vault().len(), 64);
        for id in ids {
            assert!(reopened.vault().get(&id).is_some(), "missing entry {id}");
        }
    }

    /// **Serialization is deterministic in structure**: the same content serialized twice
    /// must have the same length, the same header bytes and the same record order.
    ///
    /// The nonces are random, so the two byte strings differ; what must agree is the
    /// content after parsing back, which is what this checks.
    #[test]
    fn serialization_is_deterministic_in_structure() {
        let mut file = VaultFile::create().expect("OS randomness available");
        for i in 0..16 {
            file.vault_mut()
                .insert(sample_entry(&format!("e{i}")))
                .expect("insertion succeeds");
        }
        let a = file.serialize().expect("serialization succeeds");
        let b = file.serialize().expect("serialization succeeds");

        assert_eq!(a.len(), b.len(), "two serializations differ in length");
        assert_eq!(a[..9], b[..9], "magic and version must match");
        assert_eq!(a[9], b[9], "the reserved byte must match");

        let names = |bytes: &[u8]| -> Vec<String> {
            let f = VaultFile::parse(
                MasterKey::from_bytes(master_key_to_bytes(file.master_key()))
                    .expect("correct length"),
                bytes,
            )
            .expect("parsing succeeds");
            f.vault().iter().map(|(_, e)| e.name.clone()).collect()
        };
        assert_eq!(names(&a), names(&b), "the entry order is nondeterministic");
    }

    /// A different master key cannot open the file.
    #[test]
    fn wrong_master_key_cannot_open() {
        let mut file = VaultFile::create().expect("OS randomness available");
        file.vault_mut()
            .insert(sample_entry("x"))
            .expect("insertion succeeds");
        let bytes = file.serialize().expect("serialization succeeds");

        let other = MasterKey::generate().expect("OS randomness available");
        let err = VaultFile::parse(other, &bytes);
        assert!(matches!(err, Err(Error::VaultDecryptionFailed)));
    }

    /// **Flipping any single byte must be detected.**
    ///
    /// Structural bytes (magic, version, reserved byte, record count, record header) give
    /// a structural error; the nonce and the ciphertext give an authentication failure.
    /// Both are a refusal - no single flipped byte may still decrypt into plausible data.
    #[test]
    fn tampering_any_byte_is_rejected() {
        let mut file = VaultFile::create().expect("OS randomness available");
        file.vault_mut()
            .insert(sample_entry("x"))
            .expect("insertion succeeds");
        file.vault_mut()
            .insert(sample_hotp_entry())
            .expect("insertion succeeds");
        let bytes = file.serialize().expect("serialization succeeds");
        let key_bytes = master_key_to_bytes(file.master_key());

        for index in 0..bytes.len() {
            let mut tampered = bytes.clone();
            tampered[index] ^= 0x01;
            let result = VaultFile::parse(
                MasterKey::from_bytes(key_bytes.clone()).expect("correct length"),
                &tampered,
            );
            assert!(
                result.is_err(),
                "byte {index} was flipped ({:#04x} -> {:#04x}) yet still accepted",
                bytes[index],
                tampered[index]
            );
        }
    }

    /// Truncating the file at any position is rejected.
    #[test]
    fn truncation_at_any_point_is_rejected() {
        let mut file = VaultFile::create().expect("OS randomness available");
        file.vault_mut()
            .insert(sample_entry("x"))
            .expect("insertion succeeds");
        file.vault_mut()
            .insert(sample_hotp_entry())
            .expect("insertion succeeds");
        let first_id = *file.vault().iter().next().expect("has an entry").0;
        file.vault_mut().remove(&first_id, 1);
        let bytes = file.serialize().expect("serialization succeeds");
        let key_bytes = master_key_to_bytes(file.master_key());

        for cut in 1..bytes.len() {
            let result = VaultFile::parse(
                MasterKey::from_bytes(key_bytes.clone()).expect("correct length"),
                &bytes[..cut],
            );
            assert!(
                result.is_err(),
                "truncating to {cut} bytes was still accepted"
            );
        }
    }

    /// Appended bytes are rejected: ignoring them silently would make "the file was
    /// modified" disappear.
    #[test]
    fn trailing_bytes_are_rejected() {
        let mut file = VaultFile::create().expect("OS randomness available");
        file.vault_mut()
            .insert(sample_entry("x"))
            .expect("insertion succeeds");
        let mut bytes = file.serialize().expect("serialization succeeds");
        bytes.push(0x00);

        let err = VaultFile::parse(
            MasterKey::from_bytes(master_key_to_bytes(file.master_key())).expect("correct length"),
            &bytes,
        );
        assert!(matches!(err, Err(Error::VaultTrailingBytes { count: 1 })));
    }

    #[test]
    fn bad_magic_is_rejected() {
        let file = VaultFile::create().expect("OS randomness available");
        let mut bytes = file.serialize().expect("serialization succeeds");
        bytes[0] = b'X';
        let err = VaultFile::parse(
            MasterKey::from_bytes(master_key_to_bytes(file.master_key())).expect("correct length"),
            &bytes,
        );
        assert!(matches!(err, Err(Error::VaultBadMagic)));
    }

    #[test]
    fn unsupported_version_is_rejected() {
        let file = VaultFile::create().expect("OS randomness available");
        let mut bytes = file.serialize().expect("serialization succeeds");
        bytes[8] = 99;
        let err = VaultFile::parse(
            MasterKey::from_bytes(master_key_to_bytes(file.master_key())).expect("correct length"),
            &bytes,
        );
        match err {
            Err(Error::VaultUnsupportedVersion { version }) => assert_eq!(version, 99),
            other => panic!(
                "an unknown version must be rejected, actual ok={}",
                other.is_ok()
            ),
        }
    }

    #[test]
    fn nonzero_reserved_byte_is_rejected() {
        let file = VaultFile::create().expect("OS randomness available");
        let mut bytes = file.serialize().expect("serialization succeeds");
        bytes[9] = 1;
        let err = VaultFile::parse(
            MasterKey::from_bytes(master_key_to_bytes(file.master_key())).expect("correct length"),
            &bytes,
        );
        assert!(matches!(
            err,
            Err(Error::VaultReservedByteNotZero { value: 1 })
        ));
    }

    #[test]
    fn unknown_record_kind_is_rejected() {
        let mut file = VaultFile::create().expect("OS randomness available");
        file.vault_mut()
            .insert(sample_entry("x"))
            .expect("insertion succeeds");
        let mut bytes = file.serialize().expect("serialization succeeds");
        bytes[14] = 0x7F;
        let err = VaultFile::parse(
            MasterKey::from_bytes(master_key_to_bytes(file.master_key())).expect("correct length"),
            &bytes,
        );
        assert!(matches!(
            err,
            Err(Error::VaultUnknownRecordKind { value: 0x7F })
        ));
    }

    #[test]
    fn duplicate_entry_id_is_rejected() {
        let mut file = VaultFile::create().expect("OS randomness available");
        let id = file
            .vault_mut()
            .insert(sample_entry("x"))
            .expect("insertion succeeds");

        let mut vault = Vault::new();
        vault
            .insert_with_id(id, sample_entry("a"))
            .expect("first insertion");
        let err = vault.insert_with_id(id, sample_entry("b"));
        assert!(matches!(err, Err(Error::VaultDuplicateEntryId)));

        assert_eq!(vault.len(), 1);
        assert_eq!(vault.get(&id).expect("entry exists").name, "a");
    }

    /// `replace` renames in place: the ID stays, no tombstone is left, and the caller can
    /// preserve the creation time.
    #[test]
    fn replace_keeps_the_id_and_leaves_no_tombstone() {
        let mut vault = Vault::new();
        let id = vault
            .insert(sample_entry("original"))
            .expect("insertion succeeds");
        let created = vault.get(&id).expect("entry exists").created_at;

        let mut renamed = sample_entry("renamed");
        renamed.created_at = created;
        vault
            .replace(id, renamed)
            .expect("replacement must succeed");

        let entry = vault
            .get(&id)
            .expect("the identifier must still point at that entry");
        assert_eq!(entry.name, "renamed");
        assert_eq!(
            entry.created_at, created,
            "the creation time must be preserved"
        );
        assert_eq!(vault.len(), 1, "a replacement must not add an entry");
        assert_eq!(
            vault.tombstone_count(),
            0,
            "a rename is not a deletion and must not leave a tombstone: the tombstone gets synced out and the other side may really delete the entry because of it"
        );
    }

    /// Replacing a missing entry is an error rather than a silent insert, and it must not
    /// add the entry back.
    #[test]
    fn replace_of_a_missing_entry_is_rejected() {
        let mut vault = Vault::new();
        let missing = EntryId::from_bytes([0x5A; EntryId::LEN]);
        let err = vault.replace(missing, sample_entry("ghost"));
        assert!(matches!(err, Err(Error::VaultEntryNotFound)));
        assert!(vault.is_empty(), "a failure must not conjure up an entry");
    }

    /// An empty vault round-trips, and its file is the 14-byte header plus the master key
    /// check value.
    #[test]
    fn empty_vault_roundtrips() {
        let file = VaultFile::create().expect("OS randomness available");
        let bytes = file.serialize().expect("serialization succeeds");
        assert_eq!(
            bytes.len(),
            14 + crypto::KEY_CHECK_LEN,
            "an empty file must be the header plus the master key check value"
        );
        let reopened = VaultFile::parse(
            MasterKey::from_bytes(master_key_to_bytes(file.master_key())).expect("correct length"),
            &bytes,
        )
        .expect("parsing succeeds");
        assert!(reopened.vault().is_empty());
        assert_eq!(reopened.vault().tombstone_count(), 0);
    }

    /// An **empty** vault detects a wrong master key: the check value is decidable even
    /// when there are zero records to authenticate.
    #[test]
    fn an_empty_vault_detects_a_wrong_master_key() {
        let file = VaultFile::create().expect("OS randomness available");
        assert!(
            file.vault().is_empty(),
            "precondition: this vault really is empty"
        );
        let bytes = file.serialize().expect("serialization succeeds");

        let wrong = MasterKey::generate().expect("OS randomness available");
        assert_ne!(
            wrong.expose(),
            file.master_key().expose(),
            "the two keys must differ"
        );

        let err = VaultFile::parse(wrong, &bytes);
        assert!(
            matches!(err, Err(Error::VaultDecryptionFailed)),
            "an empty vault must be rejected with the wrong key too, actual ok={}",
            err.is_ok()
        );
    }

    /// A version 1 file is still readable: version byte 1, no trailing check value, record
    /// AAD version 1. Built by hand because serialization always writes the current version
    /// now; the property pinned here is the byte layout itself.
    #[test]
    fn version_1_files_are_still_readable() {
        let master = MasterKey::generate().expect("OS randomness available");
        let id = EntryId::generate().expect("OS randomness available");
        let entry = sample_entry("old-format");
        let plaintext = encode_entry(&entry).expect("encoding succeeds");
        let (nonce, ciphertext) =
            crypto::seal(&master, RecordKind::Entry, id.as_bytes(), 1, &plaintext)
                .expect("sealing succeeds");

        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.push(1);
        out.push(0);
        put_u32(&mut out, 1);
        out.push(RecordKind::Entry.as_byte());
        out.extend_from_slice(id.as_bytes());
        out.extend_from_slice(&nonce);
        put_u32(
            &mut out,
            u32::try_from(ciphertext.len()).expect("the test data is far below u32::MAX"),
        );
        out.extend_from_slice(&ciphertext);

        let reopened = VaultFile::parse(
            MasterKey::from_bytes(master_key_to_bytes(&master)).expect("correct length"),
            &out,
        )
        .expect("a version 1 file must still parse");
        assert_eq!(reopened.vault().len(), 1, "the entry must be read back");
        assert_eq!(
            reopened.vault().iter().next().expect("one entry").1.name,
            "old-format"
        );

        let wrong = MasterKey::generate().expect("OS randomness available");
        assert!(
            VaultFile::parse(wrong, &out).is_err(),
            "a version 1 file with content must fail under the wrong key"
        );
    }

    /// Builds a valid entry of the given kind, for codec round trips.
    fn entry_with_kind(kind: EntryKind) -> VaultEntry {
        Entry::new(
            "kind".into(),
            Some("Example".into()),
            "alice".into(),
            secret(),
            otp::Algorithm::Sha1,
            otp::Digits::SIX,
            kind,
            String::new(),
            1_700_000_000,
            1_700_000_000,
        )
        .expect("valid entry")
    }

    /// Builds an entry plaintext the way **format version 2** wrote it: no kind node.
    ///
    /// Written by hand rather than through [`encode_entry`], which always writes a kind node
    /// now. A round trip through the current encoder therefore cannot stand in for a version 2
    /// file: it would prove only that this build agrees with itself.
    fn version_2_plaintext(with_counter: bool) -> Vec<u8> {
        let mut out = Vec::new();
        put_node(&mut out, tag::NAME, b"legacy");
        put_node(&mut out, tag::ACCOUNT, b"alice");
        put_node(&mut out, tag::SECRET, b"JBSWY3DPEHPK3PXP");
        put_node(&mut out, tag::ALGORITHM, &[tag::ALG_SHA1]);
        put_node(&mut out, tag::DIGITS, &[otp::Digits::SIX.as_byte()]);
        put_node(&mut out, tag::PERIOD, &30_u64.to_be_bytes());
        if with_counter {
            put_node(&mut out, tag::COUNTER, &7_u64.to_be_bytes());
        }
        put_node(&mut out, tag::NOTE, b"");
        put_node(&mut out, tag::CREATED_AT, &0_u64.to_be_bytes());
        put_node(&mut out, tag::UPDATED_AT, &0_u64.to_be_bytes());
        out
    }

    /// A version 2 file is still readable: version byte 2, the trailing master key check
    /// value, record AAD version 2, and a plaintext without a kind node. Built by hand because
    /// serialization always writes the current version now; the property pinned here is the
    /// byte layout itself.
    #[test]
    fn version_2_files_are_still_readable() {
        let master = MasterKey::generate().expect("OS randomness available");
        let id = EntryId::generate().expect("OS randomness available");
        let plaintext = version_2_plaintext(false);
        let (nonce, ciphertext) =
            crypto::seal(&master, RecordKind::Entry, id.as_bytes(), 2, &plaintext)
                .expect("sealing succeeds");

        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.push(2);
        out.push(0);
        put_u32(&mut out, 1);
        out.push(RecordKind::Entry.as_byte());
        out.extend_from_slice(id.as_bytes());
        out.extend_from_slice(&nonce);
        put_u32(
            &mut out,
            u32::try_from(ciphertext.len()).expect("the test data is far below u32::MAX"),
        );
        out.extend_from_slice(&ciphertext);
        out.extend_from_slice(&crypto::key_check(&master));

        let reopened = VaultFile::parse(
            MasterKey::from_bytes(master_key_to_bytes(&master)).expect("correct length"),
            &out,
        )
        .expect("a version 2 file must still parse");
        assert_eq!(reopened.vault().len(), 1, "the entry must be read back");
        let (restored_id, restored) = reopened.vault().iter().next().expect("one entry");
        assert_eq!(*restored_id, id, "the identifier survives");
        assert_eq!(restored.name, "legacy");
        assert_eq!(
            restored.kind,
            EntryKind::Totp { period: 30 },
            "a version 2 plaintext has no kind node, so the old rule decides"
        );

        // Unlike version 1, the check value refuses a wrong key before any record is read.
        let wrong = MasterKey::generate().expect("OS randomness available");
        assert!(
            VaultFile::parse(wrong, &out).is_err(),
            "a version 2 file must fail under the wrong key"
        );
    }

    /// A plaintext with no kind node is read by the **older rule**: a counter node means HOTP,
    /// its absence means TOTP.
    ///
    /// Asserted on the decoded plaintext rather than through a round trip; the round trip would
    /// only prove that the encoder and decoder agree with each other.
    #[test]
    fn a_plaintext_without_a_kind_node_falls_back_to_the_old_rule() {
        let totp = decode_entry(&version_2_plaintext(false)).expect("a version 2 plaintext parses");
        assert_eq!(totp.kind, EntryKind::Totp { period: 30 });

        let hotp = decode_entry(&version_2_plaintext(true)).expect("a version 2 plaintext parses");
        assert_eq!(hotp.kind, EntryKind::Hotp { counter: 7 });
    }

    /// Every kind survives the codec, PINs and steps included.
    ///
    /// The kinds are listed one by one rather than derived from a list of constants, so adding
    /// a variant without teaching the codec about it fails here.
    #[test]
    fn every_entry_kind_round_trips() {
        let kinds = [
            EntryKind::Totp { period: 45 },
            EntryKind::Hotp { counter: 9_999 },
            EntryKind::Motp {
                period: 10,
                pin: Some(crate::motp::MotpPin::new("1234".to_owned())),
            },
            EntryKind::Motp {
                period: 10,
                pin: None,
            },
            EntryKind::Yandex {
                period: 30,
                pin: Some(crate::yaotp::YandexPin::new("7586".to_owned())),
            },
            EntryKind::Yandex {
                period: 60,
                pin: None,
            },
            EntryKind::Steam,
        ];

        for kind in kinds {
            let entry = entry_with_kind(kind);
            let encoded = encode_entry(&entry).expect("encoding succeeds");
            let decoded = decode_entry(&encoded).expect("the encoded entry must decode");
            assert_entry_eq(&entry, &decoded);
        }
    }

    /// A PIN node is rejected on a scheme that has no PIN.
    #[test]
    fn a_pin_node_on_a_scheme_without_a_pin_is_rejected() {
        for kind in [tag::KIND_TOTP, tag::KIND_HOTP, tag::KIND_STEAM] {
            let mut plaintext = Vec::new();
            put_node(&mut plaintext, tag::NAME, b"n");
            put_node(&mut plaintext, tag::ACCOUNT, b"a");
            put_node(&mut plaintext, tag::SECRET, b"secret");
            put_node(&mut plaintext, tag::ALGORITHM, &[tag::ALG_SHA1]);
            put_node(&mut plaintext, tag::DIGITS, &[otp::Digits::SIX.as_byte()]);
            put_node(&mut plaintext, tag::ENTRY_KIND, &[kind]);
            put_node(&mut plaintext, tag::PERIOD, &30_u64.to_be_bytes());
            put_node(&mut plaintext, tag::MOTP_PIN, b"1234");
            put_node(&mut plaintext, tag::CREATED_AT, &0_u64.to_be_bytes());
            assert!(
                matches!(decode_entry(&plaintext), Err(Error::VaultCorrupt)),
                "a PIN on a scheme without one must be rejected"
            );
        }
    }

    /// A scheme's step must be present, and an unknown kind byte is never guessed.
    #[test]
    fn an_unknown_or_incomplete_kind_is_rejected() {
        let base = |kind: Option<u8>, period: bool| {
            let mut plaintext = Vec::new();
            put_node(&mut plaintext, tag::NAME, b"n");
            put_node(&mut plaintext, tag::ACCOUNT, b"a");
            put_node(&mut plaintext, tag::SECRET, b"secret");
            put_node(&mut plaintext, tag::ALGORITHM, &[tag::ALG_SHA1]);
            put_node(&mut plaintext, tag::DIGITS, &[otp::Digits::SIX.as_byte()]);
            if let Some(kind) = kind {
                put_node(&mut plaintext, tag::ENTRY_KIND, &[kind]);
            }
            if period {
                put_node(&mut plaintext, tag::PERIOD, &30_u64.to_be_bytes());
            }
            put_node(&mut plaintext, tag::CREATED_AT, &0_u64.to_be_bytes());
            plaintext
        };

        assert!(
            matches!(decode_entry(&base(Some(0), true)), Err(Error::VaultCorrupt)),
            "kind byte 0 is not a scheme"
        );
        assert!(
            matches!(
                decode_entry(&base(Some(tag::KIND_STEAM + 1), true)),
                Err(Error::VaultCorrupt)
            ),
            "a kind byte from a newer version must be rejected, not guessed"
        );
        assert!(
            matches!(
                decode_entry(&base(Some(tag::KIND_MOTP), false)),
                Err(Error::VaultCorrupt)
            ),
            "a kind carrying a step must have one"
        );
        assert!(
            matches!(
                decode_entry(&base(Some(tag::KIND_HOTP), true)),
                Err(Error::VaultCorrupt)
            ),
            "HOTP needs a counter, not a step"
        );
        assert!(
            decode_entry(&base(Some(tag::KIND_TOTP), true)).is_ok(),
            "a complete TOTP entry is accepted"
        );
    }

    /// A repeated node is rejected for the **new** tags too.
    ///
    /// The duplicate check keeps one bit per known tag, so it has to cover the tags added with
    /// the entry kind: a bitmap that stopped at the older tag range would let a second kind
    /// node, or a second PIN node, slip through and be decided by whichever came last.
    #[test]
    fn duplicate_nodes_are_rejected_for_the_new_tags_too() {
        for duplicated in [tag::ENTRY_KIND, tag::MOTP_PIN, tag::YANDEX_PIN] {
            let mut plaintext = Vec::new();
            put_node(&mut plaintext, tag::NAME, b"n");
            put_node(&mut plaintext, tag::ACCOUNT, b"a");
            put_node(&mut plaintext, tag::SECRET, b"secret");
            put_node(&mut plaintext, tag::ALGORITHM, &[tag::ALG_SHA1]);
            put_node(&mut plaintext, tag::DIGITS, &[otp::Digits::SIX.as_byte()]);
            put_node(&mut plaintext, tag::PERIOD, &30_u64.to_be_bytes());
            put_node(&mut plaintext, tag::CREATED_AT, &0_u64.to_be_bytes());
            for _ in 0..2 {
                let payload: &[u8] = match duplicated {
                    tag::ENTRY_KIND => &[tag::KIND_TOTP],
                    _ => b"1234",
                };
                put_node(&mut plaintext, duplicated, payload);
            }

            match decode_entry(&plaintext) {
                Err(Error::VaultDuplicateField { tag }) => assert_eq!(tag, duplicated),
                other => panic!(
                    "tag {duplicated:#04x} appearing twice must be rejected, actual {}",
                    if other.is_ok() { "ok" } else { "another error" }
                ),
            }
        }
    }

    /// The "old files stay readable" promise, pinned against the list itself.
    ///
    /// The versions are named literally: deriving them from [`FORMAT_VERSION`] is exactly the
    /// mistake this catches (`&[1, FORMAT_VERSION]` silently dropped version 2).
    #[test]
    fn every_previous_format_version_stays_readable() {
        assert!(READABLE_VERSIONS.contains(&1), "version 1 was dropped");
        assert!(READABLE_VERSIONS.contains(&2), "version 2 was dropped");
        assert!(
            READABLE_VERSIONS.contains(&FORMAT_VERSION),
            "the current version is not in the readable list"
        );
    }

    /// Every file this build writes declares the current version, whatever it contains.
    ///
    /// The version is decided unconditionally rather than derived from the contents: a
    /// content-derived version would be a branch that itself needs independent verification,
    /// and nothing was lost between versions 2 and 3, so there is no reason to keep writing
    /// the older number.
    #[test]
    fn serialization_always_writes_the_current_version() {
        let empty = VaultFile::create().expect("OS randomness available");
        let bytes = empty.serialize().expect("serialization succeeds");
        assert_eq!(bytes[8], FORMAT_VERSION, "an empty vault");
        assert_eq!(bytes[8], 4, "the format version changed");

        let mut totp_only = VaultFile::create().expect("OS randomness available");
        totp_only
            .vault_mut()
            .insert(sample_entry("totp"))
            .expect("insertion succeeds");
        let bytes = totp_only.serialize().expect("serialization succeeds");
        assert_eq!(bytes[8], 4, "a vault holding only a TOTP entry");

        let mut hotp = VaultFile::create().expect("OS randomness available");
        hotp.vault_mut()
            .insert(sample_hotp_entry())
            .expect("insertion succeeds");
        let bytes = hotp.serialize().expect("serialization succeeds");
        assert_eq!(bytes[8], 4, "a vault holding only an HOTP entry");
    }

    /// A version 1 file with zero records parses under any key: it has no check value.
    /// Known limit of that format, pinned so it is not mistaken for fixed.
    #[test]
    fn a_version_1_empty_file_still_cannot_detect_a_wrong_key() {
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.push(1);
        out.push(0);
        put_u32(&mut out, 0);

        let wrong = MasterKey::generate().expect("OS randomness available");
        let parsed = VaultFile::parse(wrong, &out);
        assert!(
            parsed.is_ok(),
            "an empty version 1 file has no check value, so any key parses it; that is a known limitation of that format"
        );
    }

    /// Flipping any byte of the key check value is rejected.
    #[test]
    fn a_tampered_key_check_is_rejected() {
        let file = VaultFile::create().expect("OS randomness available");
        let master =
            MasterKey::from_bytes(master_key_to_bytes(file.master_key())).expect("correct length");
        let bytes = file.serialize().expect("serialization succeeds");

        for index in 0..crypto::KEY_CHECK_LEN {
            let mut tampered = bytes.clone();
            let last = tampered.len() - crypto::KEY_CHECK_LEN + index;
            tampered[last] ^= 0x01;
            let err = VaultFile::parse(
                MasterKey::from_bytes(master_key_to_bytes(&master)).expect("correct length"),
                &tampered,
            );
            assert!(
                matches!(err, Err(Error::VaultDecryptionFailed)),
                "check value byte {index} was flipped yet still accepted"
            );
        }
    }

    /// A truncated key check value reports a **structural** error, not a decryption
    /// failure: the two are handled differently by the UI (unusable file versus wrong key),
    /// so merging them would send the user after the wrong problem.
    #[test]
    fn a_truncated_key_check_is_a_structural_error() {
        let file = VaultFile::create().expect("OS randomness available");
        let master =
            MasterKey::from_bytes(master_key_to_bytes(file.master_key())).expect("correct length");
        let bytes = file.serialize().expect("serialization succeeds");

        let mut cut = bytes.clone();
        cut.truncate(cut.len() - 3);
        let err = VaultFile::parse(
            MasterKey::from_bytes(master_key_to_bytes(&master)).expect("correct length"),
            &cut,
        );
        assert!(
            matches!(err, Err(Error::VaultTruncated)),
            "a truncated check value must report truncation, actual ok={}",
            err.is_ok()
        );

        let err = crypto::verify_key_check(&master, &[0_u8; 8]);
        assert!(
            matches!(err, Err(Error::VaultBadKeyCheck)),
            "a length mismatch must report VaultBadKeyCheck"
        );
    }

    /// The file header layout is an external contract, pinned here.
    #[test]
    fn file_header_layout_is_stable() {
        let file = VaultFile::create().expect("OS randomness available");
        let bytes = file.serialize().expect("serialization succeeds");
        assert_eq!(&bytes[..8], MAGIC);
        assert_eq!(bytes[8], FORMAT_VERSION);
        assert_eq!(bytes[9], 0, "reserved byte");
        assert_eq!(
            u32::from_be_bytes(bytes[10..14].try_into().expect("4 bytes")),
            0
        );
    }

    /// An unknown node tag is skipped rather than rejected - the whole of forward
    /// compatibility.
    #[test]
    fn unknown_entry_node_is_skipped() {
        let entry = sample_entry("x");
        let mut plaintext = encode_entry(&entry).expect("encoding succeeds");

        plaintext.push(0xEE);
        put_bytes(&mut plaintext, b"future field");

        let decoded = decode_entry(&plaintext).expect("unknown nodes must be skipped");
        assert_entry_eq(&entry, &decoded);
    }

    /// Skipping an unknown node consumes exactly its declared length.
    #[test]
    fn skipping_unknown_node_uses_its_length() {
        let entry = sample_entry("x");
        let mut plaintext = Vec::new();
        plaintext.push(0xEE);
        put_bytes(&mut plaintext, &[0xAA; 100]);
        plaintext.extend_from_slice(&encode_entry(&entry).expect("encoding succeeds"));

        let decoded = decode_entry(&plaintext).expect("must skip 100 bytes");
        assert_entry_eq(&entry, &decoded);
    }

    /// An unknown tag whose length exceeds the remaining data is rejected rather than read
    /// out of range.
    #[test]
    fn unknown_node_with_overlong_length_is_rejected() {
        let mut plaintext = Vec::new();
        plaintext.push(0xEE);
        put_u32(&mut plaintext, 9999);
        plaintext.extend_from_slice(b"short");
        let err = decode_entry(&plaintext);
        assert!(matches!(err, Err(Error::VaultTruncated)));
    }

    /// A repeated known node is rejected.
    #[test]
    fn duplicate_known_node_is_rejected() {
        let mut plaintext = Vec::new();
        put_node(&mut plaintext, tag::NAME, b"first");
        put_node(&mut plaintext, tag::NAME, b"second");
        let err = decode_entry(&plaintext);
        assert!(matches!(err, Err(Error::VaultDuplicateField { .. })));
    }

    /// A missing required node is rejected.
    #[test]
    fn missing_required_node_is_rejected() {
        let mut plaintext = Vec::new();
        put_node(&mut plaintext, tag::NAME, b"only a name");
        let err = decode_entry(&plaintext);
        assert!(matches!(err, Err(Error::VaultCorrupt)));
    }

    /// An empty secret node is rejected.
    #[test]
    fn empty_secret_node_is_rejected() {
        let mut plaintext = Vec::new();
        put_node(&mut plaintext, tag::NAME, b"n");
        put_node(&mut plaintext, tag::ACCOUNT, b"a");
        put_node(&mut plaintext, tag::SECRET, b"");
        put_node(&mut plaintext, tag::ALGORITHM, &[tag::ALG_SHA1]);
        put_node(&mut plaintext, tag::DIGITS, &[otp::Digits::SIX.as_byte()]);
        put_node(&mut plaintext, tag::PERIOD, &30_u64.to_be_bytes());
        put_node(&mut plaintext, tag::CREATED_AT, &0_u64.to_be_bytes());
        let err = decode_entry(&plaintext);
        assert!(matches!(err, Err(Error::SecretEmpty)));
    }

    /// A non-UTF-8 text node is rejected rather than replaced lossily.
    #[test]
    fn invalid_utf8_is_rejected() {
        let mut plaintext = Vec::new();
        put_node(&mut plaintext, tag::NAME, &[0xFF, 0xFE]);
        put_node(&mut plaintext, tag::ACCOUNT, b"a");
        put_node(&mut plaintext, tag::SECRET, b"secret");
        put_node(&mut plaintext, tag::ALGORITHM, &[tag::ALG_SHA1]);
        put_node(&mut plaintext, tag::DIGITS, &[otp::Digits::SIX.as_byte()]);
        put_node(&mut plaintext, tag::PERIOD, &30_u64.to_be_bytes());
        put_node(&mut plaintext, tag::CREATED_AT, &0_u64.to_be_bytes());
        let err = decode_entry(&plaintext);
        assert!(matches!(err, Err(Error::VaultInvalidUtf8)));
    }

    /// Algorithm and digit bytes round-trip through the storage format, and unknown values
    /// are rejected rather than defaulted.
    #[test]
    fn algorithm_and_digits_bytes_roundtrip() {
        for algorithm in [
            otp::Algorithm::Sha1,
            otp::Algorithm::Sha256,
            otp::Algorithm::Sha512,
        ] {
            assert_eq!(
                algorithm_from_byte(algorithm_to_byte(algorithm)),
                Some(algorithm)
            );
        }
        for count in otp::Digits::MIN..=otp::Digits::MAX {
            let digits = otp::Digits::new(count).expect("1..=9 is the supported range");
            assert_eq!(
                digits_from_byte(digits_to_byte(digits)),
                Some(digits),
                "count {count}"
            );
        }
        assert_eq!(algorithm_from_byte(0), None);
        assert_eq!(algorithm_from_byte(99), None);
        assert_eq!(digits_from_byte(0), None);
        assert_eq!(digits_from_byte(10), None);
    }

    /// `None` and `Some("")` for `issuer` normalize across a round trip.
    #[test]
    fn issuer_none_and_empty_normalize() {
        let mut entry = sample_entry("x");
        entry.issuer = None;
        let decoded = decode_entry(&encode_entry(&entry).expect("encoding succeeds"))
            .expect("decoding succeeds");
        assert_eq!(decoded.issuer, None);

        entry.issuer = Some(String::new());
        let decoded = decode_entry(&encode_entry(&entry).expect("encoding succeeds"))
            .expect("decoding succeeds");
        assert_eq!(
            decoded.issuer, None,
            "an empty string must normalize to None"
        );
    }

    /// An atomic write leaves exactly the bytes passed in and leaves no temporary file
    /// behind.
    #[test]
    fn atomic_write_produces_exact_content() {
        let dir = std::env::temp_dir().join(format!("q2fa-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("directory creation succeeds");
        let path = dir.join("vault.bin");

        let data = b"hello atomic world";
        write_file_atomically(&path, data).expect("writing succeeds");
        assert_eq!(std::fs::read(&path).expect("reading succeeds"), data);

        let longer = b"a much longer replacement payload";
        write_file_atomically(&path, longer).expect("writing succeeds");
        assert_eq!(std::fs::read(&path).expect("reading succeeds"), longer);

        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .expect("listing the directory succeeds")
            .filter_map(std::result::Result::ok)
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "leftover temporary files: {leftovers:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A full write-then-read round trip preserves the vault.
    #[test]
    fn write_then_read_file_roundtrip() {
        let dir = std::env::temp_dir().join(format!("q2fa-rt-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("directory creation succeeds");
        let path = dir.join("vault.bin");

        let mut file = VaultFile::create().expect("OS randomness available");
        let id = file
            .vault_mut()
            .insert(sample_entry("GitHub"))
            .expect("insertion succeeds");
        let bytes = file.serialize().expect("serialization succeeds");
        write_file_atomically(&path, &bytes).expect("writing succeeds");

        let key =
            MasterKey::from_bytes(master_key_to_bytes(file.master_key())).expect("correct length");
        let reopened = read_file(key, &path).expect("reading back succeeds");
        assert_eq!(reopened.vault().len(), 1);
        assert_entry_eq(
            &sample_entry("GitHub"),
            reopened.vault().get(&id).expect("entry exists"),
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Reading a missing file returns an I/O error rather than panicking.
    #[test]
    fn reading_missing_file_reports_io_error() {
        let key = MasterKey::generate().expect("OS randomness available");
        let err = read_file(key, Path::new("definitely/not/here/vault.bin"));
        assert!(matches!(err, Err(Error::VaultIo { .. })));
    }

    /// Empty input is rejected without panicking.
    #[test]
    fn empty_input_is_rejected() {
        let key = MasterKey::generate().expect("OS randomness available");
        assert!(matches!(
            VaultFile::parse(key, &[]),
            Err(Error::VaultTruncated)
        ));
    }

    /// A file claiming an absurd record count is rejected, and **no allocation is
    /// attempted**.
    #[test]
    fn absurd_record_count_is_rejected() {
        let key = MasterKey::generate().expect("OS randomness available");
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        bytes.push(FORMAT_VERSION);
        bytes.push(0);
        put_u32(&mut bytes, u32::MAX);
        let err = VaultFile::parse(key, &bytes);
        assert!(matches!(err, Err(Error::VaultTooManyRecords)));
    }

    /// A file claiming an over-long record is rejected, and no allocation is attempted.
    #[test]
    fn absurd_record_length_is_rejected() {
        let key = MasterKey::generate().expect("OS randomness available");
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        bytes.push(FORMAT_VERSION);
        bytes.push(0);
        put_u32(&mut bytes, 1);
        bytes.push(0x01);
        bytes.extend_from_slice(&[0_u8; EntryId::LEN]);
        bytes.extend_from_slice(&[0_u8; NONCE_LEN]);
        put_u32(&mut bytes, u32::MAX);
        let err = VaultFile::parse(key, &bytes);
        match err {
            Err(Error::VaultRecordTooLong { limit, actual }) => {
                assert_eq!(limit, MAX_RECORD_LEN);
                assert_eq!(actual, u32::MAX as usize);
            }
            other => panic!(
                "an over-long record must be rejected, actual ok={}",
                other.is_ok()
            ),
        }
    }

    /// Unencrypted garbage is rejected (by the magic or by authentication).
    #[test]
    fn garbage_with_correct_magic_is_rejected() {
        let key = MasterKey::generate().expect("OS randomness available");
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        bytes.push(FORMAT_VERSION);
        bytes.push(0);
        put_u32(&mut bytes, 1);
        bytes.push(0x01);
        bytes.extend_from_slice(&[0x11; EntryId::LEN]);
        bytes.extend_from_slice(&[0x22; NONCE_LEN]);
        put_u32(&mut bytes, 32);
        bytes.extend_from_slice(&[0x33; 32]);
        let err = VaultFile::parse(key, &bytes);
        assert!(matches!(err, Err(Error::VaultDecryptionFailed)));
    }

    /// Writes a file from hand-built records.
    ///
    /// The record list is written in the order given, which is what decides the top group's
    /// ordering in a file that has no group records - so a test that cares about that order
    /// passes the records in the order it means.
    fn file_from_records(
        master: &MasterKey,
        records: &[(RecordKind, [u8; EntryId::LEN], Vec<u8>)],
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.push(FORMAT_VERSION);
        out.push(0);
        put_u32(
            &mut out,
            u32::try_from(records.len()).expect("the test writes a handful of records"),
        );
        for (kind, id, plaintext) in records {
            write_record(&mut out, master, FORMAT_VERSION, *kind, id, plaintext)
                .expect("sealing succeeds");
        }
        out.extend_from_slice(&crypto::key_check(master));
        out
    }

    /// A copy of the master key, since `MasterKey` is deliberately not `Clone`.
    fn copy_key(master: &MasterKey) -> MasterKey {
        MasterKey::from_bytes(master_key_to_bytes(master)).expect("the length is correct")
    }

    /// Reads the record count out of a file header.
    fn record_count(filedata: &[u8]) -> u32 {
        let bytes: [u8; 4] = filedata[10..14].try_into().expect("the header is 14 bytes");
        u32::from_be_bytes(bytes)
    }

    /// An entry record for a hand-built file.
    fn entry_record(
        master: &MasterKey,
        id: EntryId,
        name: &str,
    ) -> (RecordKind, [u8; 16], Vec<u8>) {
        let plaintext = encode_entry(&sample_entry(name)).expect("encoding succeeds");
        let _ = master;
        (RecordKind::Entry, *id.as_bytes(), plaintext)
    }

    /// Writes a file with a **declared** format version, for the compatibility fixtures.
    ///
    /// Version 1 has no master key check value; versions 2 and later do. The records must be
    /// sealed with the same version, since it takes part in the AAD.
    fn file_from_records_with_version(
        master: &MasterKey,
        version: u8,
        records: &[(RecordKind, [u8; EntryId::LEN], Vec<u8>)],
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.push(version);
        out.push(0);
        put_u32(
            &mut out,
            u32::try_from(records.len()).expect("the test writes a handful of records"),
        );
        for (kind, id, plaintext) in records {
            write_record(&mut out, master, version, *kind, id, plaintext)
                .expect("sealing succeeds");
        }
        if version >= 2 {
            out.extend_from_slice(&crypto::key_check(master));
        }
        out
    }

    /// A group record for a hand-built file, in the current (version 4) shape.
    fn group_record(id: GroupId, group: &Group) -> (RecordKind, [u8; EntryId::LEN], Vec<u8>) {
        (
            RecordKind::Group,
            *id.as_bytes(),
            encode_group(group).expect("encoding succeeds"),
        )
    }

    /// A group plaintext in the **version 1 to 3** shape: a flat position and an entry list.
    fn legacy_group_plaintext(name: &str, order: u32, entry_ids: &[EntryId]) -> Vec<u8> {
        let mut out = Vec::new();
        put_node(&mut out, tag::NAME, name.as_bytes());
        put_node(&mut out, tag::GROUP_ORDER, &order.to_be_bytes());
        let mut ids = Vec::with_capacity(entry_ids.len() * EntryId::LEN);
        for id in entry_ids {
            ids.extend_from_slice(id.as_bytes());
        }
        put_node(&mut out, tag::ENTRY_IDS, &ids);
        out
    }

    /// The node tags of a plaintext, in order, for the tests that check what is written.
    fn node_tags(plaintext: &[u8]) -> Vec<u8> {
        let mut tags = Vec::new();
        let mut at = 0;
        while at + 5 <= plaintext.len() {
            let node_tag = plaintext[at];
            let len = u32::from_be_bytes(
                plaintext[at + 1..at + 5]
                    .try_into()
                    .expect("four bytes were sliced"),
            );
            let len = usize::try_from(len).expect("the test writes small nodes");
            tags.push(node_tag);
            at += 5 + len;
        }
        tags
    }

    /// Every readable version can be read, and the current one is written.
    ///
    /// This is the compatibility promise in its smallest form: a file that exists must keep
    /// opening. The records are sealed with the version the file declares, which is what the
    /// parser expects.
    #[test]
    fn every_readable_version_parses_and_version_4_is_written() {
        let master = MasterKey::generate().expect("OS randomness available");
        let id = EntryId::generate().expect("OS randomness available");
        for version in READABLE_VERSIONS {
            let records = [(
                RecordKind::Entry,
                *id.as_bytes(),
                encode_entry(&sample_entry("x")).expect("encodes"),
            )];
            let bytes = file_from_records_with_version(&master, *version, &records);
            let parsed = VaultFile::parse(copy_key(&master), &bytes)
                .unwrap_or_else(|error| panic!("version {version} must parse: {error}"));
            assert!(parsed.vault().get(&id).is_some(), "version {version}");
            assert_eq!(*version, bytes[8]);
        }

        let file = VaultFile::create().expect("OS randomness available");
        let written = file.serialize().expect("serialization succeeds");
        assert_eq!(written[8], 4, "the current build writes format version 4");
        assert_eq!(FORMAT_VERSION, 4);
        assert_eq!(READABLE_VERSIONS, &[1, 2, 3, 4]);
    }

    /// A version 1 to 3 file has no tree: its named groups lie flat under the top group, in the
    /// order their `GROUP_ORDER` nodes say, and their entries in `ENTRY_IDS` order.
    #[test]
    fn a_legacy_file_lies_flat_under_the_top_group_in_its_declared_order() {
        let master = MasterKey::generate().expect("OS randomness available");
        let first = EntryId::generate().expect("OS randomness available");
        let second = EntryId::generate().expect("OS randomness available");
        let later = GroupId::generate().expect("OS randomness available");
        let earlier = GroupId::generate().expect("OS randomness available");

        // "Later" is written first but declares order 1; "Earlier" declares order 0.
        let bytes = file_from_records_with_version(
            &master,
            3,
            &[
                entry_record(&master, first, "first"),
                entry_record(&master, second, "second"),
                (
                    RecordKind::Group,
                    *later.as_bytes(),
                    legacy_group_plaintext("Later", 1, &[second, first]),
                ),
                (
                    RecordKind::Group,
                    *earlier.as_bytes(),
                    legacy_group_plaintext("Earlier", 0, &[]),
                ),
            ],
        );

        let parsed = VaultFile::parse(copy_key(&master), &bytes).expect("it parses");
        let order: Vec<&str> = parsed
            .vault()
            .groups()
            .map(|(_, group)| group.name.as_str())
            .collect();
        assert_eq!(
            order,
            vec!["", "Earlier", "Later"],
            "the top group comes first, then the named groups by their flat position"
        );
        assert_eq!(
            parsed.vault().ordering(&later),
            Some(vec![second, first]),
            "the entry list is read in its own order"
        );
        assert_eq!(parsed.vault().parent_of(&later), Some(GroupId::TOP));
    }

    /// A version 4 group record without its child list is corrupt, not an empty group.
    ///
    /// Guessing a flat arrangement would silently rewrite what the user arranged, so the record
    /// is refused instead.
    #[test]
    fn a_version_4_group_record_needs_its_child_list() {
        let master = MasterKey::generate().expect("OS randomness available");
        let group_id = GroupId::generate().expect("OS randomness available");
        let mut plaintext = Vec::new();
        put_node(&mut plaintext, tag::NAME, b"Work");

        let bytes = file_from_records_with_version(
            &master,
            4,
            &[(RecordKind::Group, *group_id.as_bytes(), plaintext)],
        );
        let err = VaultFile::parse(copy_key(&master), &bytes);
        assert!(matches!(err, Err(Error::VaultCorrupt)), "actual {err:?}");
    }

    /// A child kind byte this build does not know is corrupt.
    #[test]
    fn an_unknown_child_kind_is_rejected() {
        let master = MasterKey::generate().expect("OS randomness available");
        let group_id = GroupId::generate().expect("OS randomness available");
        let mut plaintext = Vec::new();
        put_node(&mut plaintext, tag::NAME, b"Work");
        let mut children = Vec::new();
        children.push(0x7F_u8);
        children.extend_from_slice(&[0x11; GroupId::LEN]);
        put_node(&mut plaintext, tag::GROUP_CHILDREN, &children);

        let bytes = file_from_records_with_version(
            &master,
            4,
            &[(RecordKind::Group, *group_id.as_bytes(), plaintext)],
        );
        let err = VaultFile::parse(copy_key(&master), &bytes);
        assert!(matches!(err, Err(Error::VaultCorrupt)), "actual {err:?}");
    }

    /// A version 4 file round-trips a tree: nested groups, entries and child groups mixed in one
    /// order, an empty group, and the depth limit.
    #[test]
    fn a_version_4_tree_round_trips() {
        let mut file = VaultFile::create().expect("OS randomness available");
        let a = file
            .vault_mut()
            .insert(sample_entry("a"))
            .expect("insertion");
        let b = file
            .vault_mut()
            .insert(sample_entry("b"))
            .expect("insertion");
        let c = file
            .vault_mut()
            .insert(sample_entry("c"))
            .expect("insertion");
        let work = file
            .vault_mut()
            .create_group("Work".to_owned())
            .expect("creation");
        let sub = file
            .vault_mut()
            .create_group_in(&work, "Sub".to_owned())
            .expect("creation");
        let empty = file
            .vault_mut()
            .create_group("Empty".to_owned())
            .expect("creation");

        file.vault_mut()
            .set_children(
                &work,
                vec![
                    GroupChild::Entry(b),
                    GroupChild::Group(sub),
                    GroupChild::Entry(a),
                ],
            )
            .expect("the list is valid");
        file.vault_mut()
            .assign_to_group(&c, &sub)
            .expect("moving succeeds");

        let bytes = file.serialize().expect("serialization succeeds");
        let parsed = VaultFile::parse(copy_key(file.master_key()), &bytes).expect("it parses back");

        assert_eq!(
            parsed.vault().children_of(&work),
            Some(
                [
                    GroupChild::Entry(b),
                    GroupChild::Group(sub),
                    GroupChild::Entry(a)
                ]
                .as_slice()
            ),
            "the mixed order survives the file"
        );
        assert_eq!(
            parsed.vault().ordering(&sub),
            Some(vec![c]),
            "the nested group keeps its entry"
        );
        assert_eq!(
            parsed.vault().ordering(&empty),
            Some(Vec::new()),
            "an empty group is a group"
        );
        assert_eq!(parsed.vault().depth_of(&sub), Some(2));
        assert_eq!(parsed.vault().parent_of(&sub), Some(work));
        assert_eq!(parsed.vault().parent_of(&work), Some(GroupId::TOP));
        assert_eq!(
            parsed.vault().group_of(&a),
            Some(&work),
            "the membership follows the child list"
        );

        let names: Vec<&str> = parsed
            .vault()
            .groups()
            .map(|(_, group)| group.name.as_str())
            .collect();
        assert_eq!(
            names,
            vec!["", "Work", "Sub", "Empty"],
            "groups() is a pre-order walk: the top group first, then its children depth-first"
        );
        let top = parsed.vault().top_group().expect("a top group exists");
        assert_eq!(
            top.children,
            vec![GroupChild::Group(work), GroupChild::Group(empty)],
            "c moved into Sub; the two groups stay in the order they were created"
        );
    }

    /// The version 4 group plaintext does not write the version 1 to 3 nodes.
    ///
    /// Writing both would put the same order in two representations, which is exactly what the
    /// tree model avoids.
    #[test]
    fn a_written_group_holds_one_child_list_and_no_flat_order() {
        let group = Group::new(
            "Work".to_owned(),
            vec![
                GroupChild::Entry(EntryId::from_bytes([1; EntryId::LEN])),
                GroupChild::Group(GroupId::from_bytes([2; GroupId::LEN])),
            ],
        )
        .expect("valid group");
        let encoded = encode_group(&group).expect("it encodes");
        assert_eq!(
            node_tags(&encoded),
            vec![tag::NAME, tag::GROUP_CHILDREN],
            "the flat position and the entry list belong to older versions"
        );
    }

    /// A version 1 or 2 file has **no** group records, and reading it puts every entry in the top
    /// group in the order the file listed them - then writing it back produces group records.
    #[test]
    fn a_file_without_group_records_reads_as_one_top_group_in_file_order() {
        let master = MasterKey::generate().expect("OS randomness available");
        let first = EntryId::generate().expect("OS randomness available");
        let second = EntryId::generate().expect("OS randomness available");
        let third = EntryId::generate().expect("OS randomness available");

        let bytes = file_from_records(
            &master,
            &[
                entry_record(&master, first, "first"),
                entry_record(&master, second, "second"),
                entry_record(&master, third, "third"),
            ],
        );
        assert_eq!(record_count(&bytes), 3, "three records, no group record");

        let parsed = VaultFile::parse(copy_key(&master), &bytes).expect("it parses");
        assert_eq!(
            parsed.vault().group_count(),
            1,
            "the top group is synthesized"
        );
        let top = parsed.vault().top_group().expect("a top group exists");
        assert_eq!(
            top.children,
            vec![
                GroupChild::Entry(first),
                GroupChild::Entry(second),
                GroupChild::Entry(third)
            ],
            "the top group is filled from the file order, since no record said otherwise"
        );
        assert_eq!(
            parsed.vault().group_of(&second),
            Some(&GroupId::TOP),
            "every entry is in the top group"
        );

        // Writing it back adds the group record: the file now says what was previously implied.
        let rewritten = parsed.serialize().expect("it serializes");
        assert_eq!(record_count(&rewritten), 4, "three entries and one group");

        let reparsed = VaultFile::parse(copy_key(&master), &rewritten).expect("it parses");
        let ordering: Vec<EntryId> = reparsed
            .vault()
            .entries_in(&GroupId::TOP)
            .map(|(id, _)| *id)
            .collect();
        assert_eq!(ordering, vec![first, second, third], "the order survives");
    }

    /// A reference to an entry the file does not contain is dropped instead of leaving a hole.
    #[test]
    fn a_dangling_reference_is_skipped() {
        let master = MasterKey::generate().expect("OS randomness available");
        let present = EntryId::generate().expect("OS randomness available");
        let missing = EntryId::generate().expect("OS randomness available");
        let group_id = GroupId::generate().expect("OS randomness available");

        let group = Group::new(
            "Work".to_owned(),
            vec![GroupChild::Entry(missing), GroupChild::Entry(present)],
        )
        .expect("valid group");
        let bytes = file_from_records(
            &master,
            &[
                entry_record(&master, present, "present"),
                group_record(group_id, &group),
            ],
        );

        let parsed = VaultFile::parse(copy_key(&master), &bytes).expect("it parses");
        assert_eq!(
            parsed.vault().ordering(&group_id),
            Some(vec![present]),
            "the reference to a missing entry is skipped, the rest is kept"
        );
    }

    /// When two lists name the same child, the group the walk reaches **first** keeps it.
    #[test]
    fn the_first_list_wins_a_shared_entry() {
        let master = MasterKey::generate().expect("OS randomness available");
        let shared = EntryId::generate().expect("OS randomness available");
        let first_group = GroupId::generate().expect("OS randomness available");
        let second_group = GroupId::generate().expect("OS randomness available");

        let first =
            Group::new("First".to_owned(), vec![GroupChild::Entry(shared)]).expect("valid group");
        let second =
            Group::new("Second".to_owned(), vec![GroupChild::Entry(shared)]).expect("valid group");
        let bytes = file_from_records(
            &master,
            &[
                group_record(second_group, &second),
                entry_record(&master, shared, "shared"),
                group_record(first_group, &first),
            ],
        );

        let parsed = VaultFile::parse(copy_key(&master), &bytes).expect("it parses");
        assert_eq!(
            parsed.vault().ordering(&second_group),
            Some(vec![shared]),
            "the second record came first in the file, so its claim stands"
        );
        assert_eq!(
            parsed.vault().ordering(&first_group),
            Some(Vec::new()),
            "the later list loses the reference"
        );
        assert_eq!(parsed.vault().group_of(&shared), Some(&second_group));
    }

    /// A named group that no list reaches is attached to the top group.
    #[test]
    fn a_group_without_a_parent_is_attached_to_the_top() {
        let master = MasterKey::generate().expect("OS randomness available");
        let group_id = GroupId::generate().expect("OS randomness available");
        let group = Group::new("Work".to_owned(), Vec::new()).expect("valid group");

        let bytes = file_from_records(&master, &[group_record(group_id, &group)]);
        let parsed = VaultFile::parse(copy_key(&master), &bytes).expect("it parses");
        assert_eq!(
            parsed.vault().top_group().map(|top| top.children.clone()),
            Some(vec![GroupChild::Group(group_id)]),
            "a group with no parent list hangs from the top"
        );
        assert_eq!(parsed.vault().parent_of(&group_id), Some(GroupId::TOP));
    }

    /// A cycle between two group records is broken by attaching the groups to the top.
    #[test]
    fn a_cycle_is_broken_without_dropping_a_group() {
        let master = MasterKey::generate().expect("OS randomness available");
        let a = GroupId::generate().expect("OS randomness available");
        let b = GroupId::generate().expect("OS randomness available");
        let group_a = Group::new("A".to_owned(), vec![GroupChild::Group(b)]).expect("valid");
        let group_b = Group::new("B".to_owned(), vec![GroupChild::Group(a)]).expect("valid");

        let bytes = file_from_records(
            &master,
            &[group_record(a, &group_a), group_record(b, &group_b)],
        );
        let parsed = VaultFile::parse(copy_key(&master), &bytes).expect("it parses");
        assert_eq!(parsed.vault().group_count(), 3, "top and two named groups");
        assert!(parsed.vault().depth_of(&a).is_some());
        assert!(parsed.vault().depth_of(&b).is_some());
        assert!(
            parsed.vault().parent_of(&a) == Some(GroupId::TOP)
                || parsed.vault().parent_of(&b) == Some(GroupId::TOP),
            "at least one end of the cycle must hang from the top"
        );
    }

    /// A group nested deeper than the limit is attached to the top instead of dropped.
    #[test]
    fn a_group_nested_too_deeply_is_attached_to_the_top() {
        let master = MasterKey::generate().expect("OS randomness available");
        let a = GroupId::generate().expect("OS randomness available");
        let b = GroupId::generate().expect("OS randomness available");
        let c = GroupId::generate().expect("OS randomness available");
        let d = GroupId::generate().expect("OS randomness available");

        let group_a = Group::new("A".to_owned(), vec![GroupChild::Group(b)]).expect("valid");
        let group_b = Group::new("B".to_owned(), vec![GroupChild::Group(c)]).expect("valid");
        let group_c = Group::new("C".to_owned(), vec![GroupChild::Group(d)]).expect("valid");
        let group_d = Group::new("D".to_owned(), Vec::new()).expect("valid");

        let bytes = file_from_records(
            &master,
            &[
                group_record(a, &group_a),
                group_record(b, &group_b),
                group_record(c, &group_c),
                group_record(d, &group_d),
            ],
        );
        let parsed = VaultFile::parse(copy_key(&master), &bytes).expect("it parses");
        assert_eq!(parsed.vault().depth_of(&a), Some(1));
        assert_eq!(parsed.vault().depth_of(&b), Some(2));
        assert_eq!(parsed.vault().depth_of(&c), Some(3));
        assert_eq!(
            parsed.vault().depth_of(&d),
            Some(1),
            "the fourth level is attached to the top, not dropped"
        );
    }

    /// An entry no list names is appended to the top group, in file order.
    #[test]
    fn an_entry_no_list_names_lands_in_the_top_group() {
        let master = MasterKey::generate().expect("OS randomness available");
        let listed = EntryId::generate().expect("OS randomness available");
        let unlisted = EntryId::generate().expect("OS randomness available");
        let group_id = GroupId::generate().expect("OS randomness available");

        let group =
            Group::new("Work".to_owned(), vec![GroupChild::Entry(listed)]).expect("valid group");
        let bytes = file_from_records(
            &master,
            &[
                entry_record(&master, unlisted, "unlisted"),
                entry_record(&master, listed, "listed"),
                group_record(group_id, &group),
            ],
        );

        let parsed = VaultFile::parse(copy_key(&master), &bytes).expect("it parses");
        assert_eq!(parsed.vault().ordering(&group_id), Some(vec![listed]));
        assert_eq!(
            parsed.vault().ordering(&GroupId::TOP),
            Some(vec![unlisted]),
            "what no list claims belongs to the top group"
        );
    }

    /// The top group cannot be renamed or removed; its contents stay editable.
    #[test]
    fn the_top_group_cannot_be_renamed_or_removed() {
        let mut vault = Vault::new();
        let id = vault.insert(sample_entry("x")).expect("insertion succeeds");

        assert!(matches!(
            vault.rename_group(&GroupId::TOP, "Home".to_owned()),
            Err(Error::VaultTopGroupImmutable)
        ));
        assert!(matches!(
            vault.remove_group(&GroupId::TOP),
            Err(Error::VaultTopGroupImmutable)
        ));

        vault
            .set_ordering(&GroupId::TOP, vec![id])
            .expect("the ordering of the top group is what it is for");
        assert_eq!(vault.ordering(&GroupId::TOP), Some(vec![id]));
    }

    /// Insertion puts an entry in the top group, and deleting it leaves no reference behind.
    #[test]
    fn insertion_and_deletion_keep_the_top_group_consistent() {
        let mut vault = Vault::new();
        let first = vault.insert(sample_entry("a")).expect("insertion succeeds");
        let second = vault.insert(sample_entry("b")).expect("insertion succeeds");
        assert_eq!(
            vault.ordering(&GroupId::TOP),
            Some(vec![first, second]),
            "insertion appends"
        );

        vault.remove(&first, 1_700_000_000);
        assert_eq!(
            vault.ordering(&GroupId::TOP),
            Some(vec![second]),
            "a deleted entry must not stay in the ordering"
        );
        assert!(vault.group_of(&first).is_none());
    }

    /// Moving an entry between groups takes it out of the old one, and a second move out of the
    /// top group does too.
    #[test]
    fn moving_an_entry_between_groups_leaves_one_reference() {
        let mut vault = Vault::new();
        let entry = vault.insert(sample_entry("x")).expect("insertion succeeds");
        let work = vault
            .create_group("Work".to_owned())
            .expect("creation succeeds");
        let private = vault
            .create_group("Private".to_owned())
            .expect("creation succeeds");

        vault
            .assign_to_group(&entry, &work)
            .expect("the move succeeds");
        assert_eq!(vault.ordering(&work), Some(vec![entry]));
        assert_eq!(
            vault.ordering(&GroupId::TOP),
            Some(Vec::new()),
            "it left the top group"
        );

        vault
            .assign_to_group(&entry, &private)
            .expect("the second move succeeds");
        assert_eq!(vault.ordering(&private), Some(vec![entry]));
        assert_eq!(vault.ordering(&work), Some(Vec::new()));

        vault
            .assign_to_group(&entry, &work)
            .expect("moving back succeeds");
        assert_eq!(vault.ordering(&work), Some(vec![entry]));
        assert_eq!(vault.ordering(&private), Some(Vec::new()));
        assert_eq!(vault.group_of(&entry), Some(&work));
    }

    /// Setting an ordering refuses what the vault cannot represent: an unknown entry, a repeated
    /// entry, an unknown group.
    #[test]
    fn setting_an_ordering_validates_its_input() {
        let mut vault = Vault::new();
        let entry = vault.insert(sample_entry("x")).expect("insertion succeeds");
        let group = vault
            .create_group("Work".to_owned())
            .expect("creation succeeds");
        let missing = EntryId::generate().expect("OS randomness available");

        assert!(matches!(
            vault.set_ordering(&group, vec![missing]),
            Err(Error::VaultGroupUnknownEntry)
        ));
        assert!(matches!(
            vault.set_ordering(&group, vec![entry, entry]),
            Err(Error::VaultGroupDuplicateChild)
        ));
        assert!(matches!(
            vault.set_ordering(&missing_group_id(), vec![]),
            Err(Error::VaultGroupNotFound)
        ));
        assert!(matches!(
            vault.assign_to_group(&missing, &group),
            Err(Error::VaultEntryNotFound)
        ));
        assert!(matches!(
            vault.assign_to_group(&entry, &missing_group_id()),
            Err(Error::VaultGroupNotFound)
        ));
        assert_eq!(
            vault.ordering(&group),
            Some(Vec::new()),
            "a refused call must not have changed anything"
        );
    }

    /// `set_children` writes a whole list, moves a child out of its old group, and refuses what
    /// would break the tree.
    #[test]
    fn setting_children_builds_and_repairs_the_tree() {
        let mut vault = Vault::new();
        let a = vault.insert(sample_entry("a")).expect("insertion");
        let b = vault.insert(sample_entry("b")).expect("insertion");
        let work = vault
            .create_group("Work".to_owned())
            .expect("creation succeeds");
        let sub = vault
            .create_group_in(&work, "Sub".to_owned())
            .expect("creation succeeds");

        vault
            .set_children(
                &work,
                vec![
                    GroupChild::Entry(b),
                    GroupChild::Group(sub),
                    GroupChild::Entry(a),
                ],
            )
            .expect("the list is valid");
        assert_eq!(
            vault.children_of(&work),
            Some(
                [
                    GroupChild::Entry(b),
                    GroupChild::Group(sub),
                    GroupChild::Entry(a)
                ]
                .as_slice()
            )
        );
        assert_eq!(
            vault.children_of(&GroupId::TOP),
            Some([GroupChild::Group(work)].as_slice()),
            "the entries moved out of the top group"
        );
        assert_eq!(vault.group_of(&b), Some(&work));

        // Moving the child group to the top takes it out of Work's list.
        vault
            .set_children(
                &GroupId::TOP,
                vec![GroupChild::Group(work), GroupChild::Group(sub)],
            )
            .expect("the list is valid");
        assert_eq!(vault.parent_of(&sub), Some(GroupId::TOP));
        assert_eq!(
            vault.children_of(&work),
            Some([GroupChild::Entry(b), GroupChild::Entry(a)].as_slice()),
            "moving the child group out leaves the entries where they were"
        );

        // A cycle is refused.
        vault
            .set_children(&work, vec![GroupChild::Group(sub)])
            .expect("valid again");
        let err = vault.set_children(&sub, vec![GroupChild::Group(work)]);
        assert!(matches!(err, Err(Error::VaultGroupCycle)), "actual {err:?}");

        // A child the list drops is not deleted: it goes back to the top group.
        vault
            .set_children(&work, vec![GroupChild::Group(sub)])
            .expect("valid");
        assert_eq!(vault.group_of(&a), Some(&GroupId::TOP));
        assert_eq!(vault.group_of(&b), Some(&GroupId::TOP));
    }

    /// A group moved under a group that is dropped goes to the parent, not into nothing.
    #[test]
    fn removing_a_group_moves_its_children_to_its_parent() {
        let mut vault = Vault::new();
        let entry = vault.insert(sample_entry("a")).expect("insertion");
        let outer = vault
            .create_group("Outer".to_owned())
            .expect("creation succeeds");
        let inner = vault
            .create_group_in(&outer, "Inner".to_owned())
            .expect("creation succeeds");
        vault
            .assign_to_group(&entry, &inner)
            .expect("moving succeeds");

        let removed = vault
            .remove_group(&outer)
            .expect("removal succeeds")
            .expect("the group existed");
        assert_eq!(removed.name, "Outer");
        assert_eq!(
            vault.parent_of(&inner),
            Some(GroupId::TOP),
            "the child group moves to where its parent was (the top)"
        );
        assert_eq!(vault.group_of(&entry), Some(&inner), "the entry stays put");
        assert_eq!(
            vault.top_group().map(|top| top.children.clone()),
            Some(vec![GroupChild::Group(inner)]),
            "and takes the removed group's place in the parent list"
        );

        assert!(
            vault
                .remove_group(&inner)
                .expect("removal succeeds")
                .is_some()
        );
        assert_eq!(
            vault.group_of(&entry),
            Some(&GroupId::TOP),
            "its entry falls back to the top group"
        );
        assert!(
            vault
                .remove_group(&inner)
                .expect("removal succeeds")
                .is_none()
        );
    }

    /// `create_group_in` refuses a group that would be nested too deeply, and the parent of a
    /// fresh group is the top group.
    #[test]
    fn creating_a_child_group_respects_the_depth_limit() {
        let mut vault = Vault::new();
        let first = vault
            .create_group("A".to_owned())
            .expect("creation succeeds");
        let second = vault
            .create_group_in(&first, "B".to_owned())
            .expect("creation succeeds");
        let third = vault
            .create_group_in(&second, "C".to_owned())
            .expect("creation succeeds");
        assert_eq!(vault.depth_of(&third), Some(Vault::MAX_GROUP_DEPTH));
        let err = vault.create_group_in(&third, "D".to_owned());
        assert!(
            matches!(err, Err(Error::VaultGroupDepthExceeded { .. })),
            "actual {err:?}"
        );
        assert!(matches!(
            vault.create_group_in(&missing_group_id(), "X".to_owned()),
            Err(Error::VaultGroupNotFound)
        ));
        assert_eq!(vault.parent_of(&first), Some(GroupId::TOP));
    }

    /// **Moving a subtree whose height would exceed the limit is refused**, even though the group
    /// itself would still be shallow enough.
    #[test]
    fn moving_a_tall_subtree_past_the_limit_is_refused() {
        let mut vault = Vault::new();
        let deep = vault.create_group("Deep".to_owned()).expect("creation");
        let child = vault
            .create_group_in(&deep, "Child".to_owned())
            .expect("creation");
        let middle = vault.create_group("Middle".to_owned()).expect("creation");
        let target = vault
            .create_group_in(&middle, "Target".to_owned())
            .expect("creation");
        assert_eq!(vault.depth_of(&target), Some(2));

        let err = vault.set_children(&target, vec![GroupChild::Group(deep)]);
        assert!(
            matches!(err, Err(Error::VaultGroupDepthExceeded { .. })),
            "placing a two-level subtree at depth two would reach four, actual {err:?}"
        );
        let _ = child;
    }

    /// An entry carries its icon through the file, and only the icon distinguishes two otherwise
    /// identical entries.
    #[test]
    fn an_icon_survives_the_file_and_takes_part_in_equality() {
        let icon = EntryIcon::new(IconMime::Png, vec![0x89, b'P', b'N', b'G']).expect("small icon");
        let plain = sample_entry("GitHub");
        let with_icon = sample_entry("GitHub").with_icon(Some(icon.clone()));

        assert_ne!(
            plain, with_icon,
            "two entries that differ only in their icon are different entries"
        );
        assert_eq!(
            with_icon.duplicate().expect("it duplicates").icon,
            Some(icon.clone())
        );

        let debug = format!("{icon:?}");
        assert!(debug.contains("Png"), "the format is visible: {debug}");
        assert!(
            !debug.contains("137"),
            "the bytes are not printed into diagnostics: {debug}"
        );

        let mut file = VaultFile::create().expect("OS randomness available");
        let id = file.vault_mut().insert(with_icon).expect("insertion");
        let bytes = file.serialize().expect("serialization succeeds");
        let parsed = VaultFile::parse(copy_key(file.master_key()), &bytes).expect("it parses");
        let restored = parsed.vault().get(&id).expect("the entry exists");
        assert_eq!(restored.icon, Some(icon));
    }

    /// An icon whose media type this build does not know is refused at parse time.
    #[test]
    fn an_unknown_icon_media_type_is_rejected() {
        let master = MasterKey::generate().expect("OS randomness available");
        let id = EntryId::generate().expect("OS randomness available");
        let mut plaintext = encode_entry(&sample_entry("x")).expect("encodes");
        let mut payload = vec![0x7F_u8];
        payload.extend_from_slice(&[0xAA; 4]);
        put_node(&mut plaintext, tag::ICON, &payload);

        let bytes = file_from_records(&master, &[(RecordKind::Entry, *id.as_bytes(), plaintext)]);
        let err = VaultFile::parse(copy_key(&master), &bytes);
        assert!(matches!(err, Err(Error::VaultCorrupt)), "actual {err:?}");
    }

    /// An icon node whose payload is empty (no media-type byte) is corrupt.
    #[test]
    fn an_icon_without_a_media_type_is_rejected() {
        let master = MasterKey::generate().expect("OS randomness available");
        let id = EntryId::generate().expect("OS randomness available");
        let mut plaintext = Vec::new();
        put_node(&mut plaintext, tag::NAME, b"x");
        put_node(&mut plaintext, tag::ISSUER, b"");
        put_node(&mut plaintext, tag::ACCOUNT, b"a");
        put_node(&mut plaintext, tag::SECRET, b"secret");
        put_node(&mut plaintext, tag::ALGORITHM, &[tag::ALG_SHA1]);
        put_node(&mut plaintext, tag::DIGITS, &[6]);
        put_node(&mut plaintext, tag::ENTRY_KIND, &[tag::KIND_TOTP]);
        put_node(&mut plaintext, tag::PERIOD, &30_u64.to_be_bytes());
        put_node(&mut plaintext, tag::CREATED_AT, &0_u64.to_be_bytes());
        put_node(&mut plaintext, tag::ICON, &[]);

        let bytes = file_from_records(&master, &[(RecordKind::Entry, *id.as_bytes(), plaintext)]);
        let err = VaultFile::parse(copy_key(&master), &bytes);
        assert!(matches!(err, Err(Error::VaultCorrupt)), "actual {err:?}");
    }

    /// An icon larger than the node limit is refused by the encoder rather than written.
    #[test]
    fn an_oversized_icon_is_refused_before_it_is_written() {
        let mut entry = sample_entry("x");
        entry.icon = Some(EntryIcon {
            mime: IconMime::Png,
            bytes: vec![0_u8; EntryIcon::MAX_BYTES + 1],
        });
        let err = encode_entry(&entry);
        assert!(matches!(
            err,
            Err(Error::FieldTooLong { field: "icon", .. })
        ));
    }

    /// The largest icon the format allows still fits, which pins the boundary rather than only
    /// the rejection above it.
    #[test]
    fn the_largest_icon_fits_its_node() {
        let icon = EntryIcon::new(IconMime::Jpeg, vec![0x42; EntryIcon::MAX_BYTES])
            .expect("the boundary is allowed");
        let entry = sample_entry("x").with_icon(Some(icon.clone()));
        let encoded = encode_entry(&entry).expect("it encodes");
        let decoded = decode_entry(&encoded).expect("it decodes");
        assert_eq!(decoded.icon, Some(icon));
    }

    /// A group identifier that is not in the vault.
    fn missing_group_id() -> GroupId {
        GroupId::from_bytes([0xAB; GroupId::LEN])
    }
}
