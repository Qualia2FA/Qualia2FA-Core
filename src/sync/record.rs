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

//! Encryption and decryption of a single record: turning vault entries and tombstones into records
//! inside a payload, and back.
//!
//! # It **shares one encoding** with the vault file
//!
//! The plaintext encoding of entries and tombstones is reused wholesale from [`crate::vault`] (the
//! codecs of [`crate::vault::Entry`] and [`crate::vault::Tombstone`]). This is deliberate:
//!
//! - **Two hand-written encodings drift.** Adding a field to the file format while forgetting the
//!   sync format shows up as "the new field is empty after syncing" — silent data loss that fails
//!   no test.
//! - **Syncing is moving the same data to another device**, with identical semantics on both
//!   sides, so there is no reason for two representations.
//!
//! **Domain separation comes from keys, not from encoding**: sync records use a subkey different
//! from the vault's ([`crate::sync::derive_record_key`]), so even if the two AADs were identical
//! byte for byte, the ciphertexts remain mutually undecryptable. See
//! [`crate::sync::HKDF_SALT_SYNC`].
//!
//! # The kind is inside the ciphertext, so decryption tries each kind
//!
//! A record's **kind** (live entry, tombstone or group) is part of the AAD, and the AAD must be
//! known before decryption — so keeping the kind out of the plaintext creates a chicken-and-egg
//! problem. Putting the kind into the plaintext under a key that does not depend on it would
//! instead make "move an entry's ciphertext into a tombstone's slot" invisible to the AEAD,
//! wasting the per-record authentication.
//!
//! The resolution is to try each kind in turn — `SyncEntry`, `SyncTombstone`, `SyncGroup` — and
//! take the one that authenticates. This introduces **no ambiguity**: the kinds have different
//! AADs, so one ciphertext cannot pass two authentications (probability on the order of 2^-128).
//! The cost is one extra Poly1305 computation per failed attempt, and failure only happens in two
//! situations: a wrong key (the very first record of the payload fails) or a tampered payload (the
//! whole sync is void). On the normal path each record authenticates on its first or second try.
//!
//! What it buys is that an attacker cannot see how many deletions this sync carries. That
//! information has limited value in itself, but it is **free** here — and it can only be got right
//! once: once a kind byte is written into the plaintext, taking it back requires a new payload
//! format version.

use crate::sync::{FORMAT_VERSION, InnerRecordKind, Record};
use crate::vault::crypto;
use crate::vault::{Entry as VaultEntry, EntryId, Group, GroupId, Tombstone};
use crate::{Error, Result};

/// Length of the entry plaintext header: magic 4 + id 16 + length 4.
///
/// The length is a **u32**, not the u16 of payload versions 1 to 3: an entry may carry an icon of
/// up to 64 KiB, and a u16 would make an icon-bearing entry "storable in the vault but not
/// syncable", failing with a malformed-record error that says nothing about icons. The group
/// header uses the same width for the same reason: its child list can approach 64 KiB.
const ENTRY_HEADER_LEN: usize = 4 + EntryId::LEN + 4;

/// Magic number of the entry plaintext header.
///
/// It fails the first check when the **encoding layer is misused** (an entry encoding fed to the
/// tombstone decoder, or a future record type dispatched to the wrong branch), instead of leaving
/// the parser to report a "field tag not recognized" error for a byte stream with completely
/// different semantics. On the normal path the AAD already binds kind + entry ID + version, so any
/// plaintext that arrives does match.
const ENTRY_MAGIC: &[u8; 4] = b"Q2FE";

/// Magic number of the group plaintext header.
///
/// A second magic for the same reason the entry encoding has one: an entry body fed to the group
/// decoder (or the reverse) is caught here rather than being half-parsed into a group with a
/// nonsense name.
const GROUP_MAGIC: &[u8; 4] = b"Q2FG";

/// A record that has been decrypted and parsed.
///
/// Kept separate from the wire type: [`crate::sync::Record`] is bytes plus an identifier, while
/// `OpenedRecord` is the semantics — an entry or a tombstone that can be merged.
#[derive(Debug, PartialEq, Eq)]
pub enum OpenedRecord {
    /// A live entry.
    Entry {
        /// Identifier of the entry. It is also the identifier of this record in the payload
        /// (checked to be equal).
        id: EntryId,
        /// The entry content.
        entry: Box<VaultEntry>,
    },
    /// A tombstone.
    Tombstone(Box<Tombstone>),
    /// A group with its ordering.
    Group {
        /// Identifier of the group. The payload carries it in the same 16-byte field an entry
        /// identifier uses, and the record kind is what tells the two apart.
        id: GroupId,
        /// The group, including the ordering of its entries.
        group: Box<Group>,
    },
}

impl OpenedRecord {
    /// The 16-byte key this record is filed under in the payload.
    ///
    /// For an entry or a tombstone that is the entry identifier; for a group it is the **group**
    /// identifier, reinterpreted: the payload layer keys its records by 16 opaque bytes and only
    /// the vault knows that one of them names a group. Use [`OpenedRecord::group_id`] when the
    /// distinction matters.
    #[must_use]
    pub fn entry_id(&self) -> EntryId {
        match self {
            Self::Entry { id, .. } => *id,
            Self::Tombstone(tombstone) => tombstone.entry_id,
            Self::Group { id, .. } => EntryId::from_bytes(*id.as_bytes()),
        }
    }

    /// The group identifier, for a group record.
    #[must_use]
    pub fn group_id(&self) -> Option<GroupId> {
        match self {
            Self::Group { id, .. } => Some(*id),
            _ => None,
        }
    }

    /// Converts this into a form that can be handed to [`crate::sync::merge_into`].
    #[must_use]
    pub fn into_merged(self) -> crate::sync::MergedRecord {
        match self {
            Self::Entry { id, entry } => crate::sync::MergedRecord::Entry { id, entry },
            Self::Tombstone(tombstone) => crate::sync::MergedRecord::Tombstone(tombstone),
            Self::Group { id, group } => crate::sync::MergedRecord::Group { id, group },
        }
    }
}

/// Encrypts an entry into a record of the payload.
///
/// `id` is the identifier of this entry in the set. The entry itself carries no identifier (see
/// [`crate::vault::Entry`]), so this function writes it into the plaintext header and it is checked
/// again on decryption — see item 2 of [`open`].
///
/// # Errors
///
/// - [`Error::SyncMalformed`]: the entry encoding exceeds [`u32::MAX`] bytes. Real entries are far
///   smaller (the longest field is capped at 64 KiB), so this only happens when the encoding logic
///   is wrong.
/// - [`Error::RandomnessUnavailable`]: the random source is unavailable.
pub fn seal_entry(key: &[u8; 32], id: &EntryId, entry: &VaultEntry) -> Result<Record> {
    let body = crate::vault::encode_entry(entry)?;
    let mut plaintext = Vec::with_capacity(ENTRY_HEADER_LEN + body.len());
    plaintext.extend_from_slice(ENTRY_MAGIC);
    plaintext.extend_from_slice(id.as_bytes());
    let len = u32::try_from(body.len()).map_err(|_| Error::SyncMalformed {
        reason: "a single entry encodes to more than 4294967295 bytes",
    })?;
    plaintext.extend_from_slice(&len.to_be_bytes());
    plaintext.extend_from_slice(&body);

    seal_plaintext(key, InnerRecordKind::SyncEntry, id, &plaintext)
}

/// Encrypts a tombstone into a record of the payload.
///
/// # Errors
///
/// [`Error::RandomnessUnavailable`]: the random source is unavailable.
pub fn seal_tombstone(key: &[u8; 32], tombstone: &Tombstone) -> Result<Record> {
    let plaintext = crate::vault::encode_tombstone(tombstone);
    seal_plaintext(
        key,
        InnerRecordKind::SyncTombstone,
        &tombstone.entry_id,
        &plaintext,
    )
}

/// Encrypts a group into a record of the payload.
///
/// The ordering travels with the group: it is what the user arranged, and on its own it means
/// nothing without the entries, which the same payload carries.
///
/// # Errors
///
/// - [`Error::SyncMalformed`]: the group encoding exceeds [`u32::MAX`] bytes.
/// - [`Error::RandomnessUnavailable`]: the random source is unavailable.
pub fn seal_group(key: &[u8; 32], id: &GroupId, group: &Group) -> Result<Record> {
    let body = crate::vault::encode_group(group)?;
    let mut plaintext = Vec::with_capacity(ENTRY_HEADER_LEN + body.len());
    plaintext.extend_from_slice(GROUP_MAGIC);
    plaintext.extend_from_slice(id.as_bytes());
    let len = u32::try_from(body.len()).map_err(|_| Error::SyncMalformed {
        reason: "a single group encodes to more than 4294967295 bytes",
    })?;
    plaintext.extend_from_slice(&len.to_be_bytes());
    plaintext.extend_from_slice(&body);

    let record_id = EntryId::from_bytes(*id.as_bytes());
    seal_plaintext(key, InnerRecordKind::SyncGroup, &record_id, &plaintext)
}

/// Seals a plaintext into a record with an already-derived subkey.
///
/// The common tail of [seal_entry] and [seal_tombstone]: the two differ only in the plaintext
/// encoding and the kind byte.
fn seal_plaintext(
    key: &[u8; 32],
    kind: InnerRecordKind,
    id: &EntryId,
    plaintext: &[u8],
) -> Result<Record> {
    let (nonce, ciphertext) =
        crypto::seal_with_key(key, kind, id.as_bytes(), FORMAT_VERSION, plaintext)?;
    Ok(Record {
        entry_id: *id,
        nonce,
        ciphertext,
    })
}

/// Decrypts and parses a record.
///
/// # What it checks
///
/// 1. **The AAD**: kind, entry ID, payload format version. Moving entry A's ciphertext into entry
///    B's slot therefore fails authentication because the ID in the AAD does not match, instead of
///    being silently accepted as B's content.
/// 2. **The identifier in the plaintext header equals `record.entry_id`**. This is **not**
///    redundant: the AAD uses `record.entry_id`, and a caller may hold a different identifier
///    obtained elsewhere when looking up the merge result. Carrying a copy inside the plaintext and
///    checking it closes the gap where "the record claims to be A while the content came from B".
/// 3. **The magic number and length in the entry plaintext header**: the header starts with `Q2FE`,
///    followed by the identifier and a u16 length. Those 4 bytes are not redundant — the AAD
///    already binds kind and identifier, but when the **encoding layer is misused** (an entry
///    encoding fed to the tombstone decoder), the first check catches it instead of leaving the
///    parser to struggle through a byte stream with completely different semantics and finally
///    report a "field tag not recognized" error pointing in the wrong direction.
///
/// Both kinds are tried — `SyncEntry` first, then `SyncTombstone` — and the one that authenticates
/// is taken; see the module documentation.
///
/// # Errors
///
/// - [`Error::SyncAuthenticationFailed`]: both kinds failed authentication. It **does not
///   distinguish** a wrong key, tampered ciphertext and an AAD mismatch — telling them apart helps
///   an attacker and has no actionable value for the user. Why **not**
///   [`Error::VaultDecryptionFailed`]: that one means "the vault file cannot be opened", and the
///   client handles it (send the user to check the master key) quite differently from "this sync
///   payload is untrustworthy".
/// - [`Error::SyncMalformed`]: the plaintext structure contradicts itself. The outer layer and the
///   AAD have both authenticated, so reaching this point means **our own encoding logic is wrong**,
///   not that we are under attack.
/// - The [`Error::VaultUnknownRecordKind`] family: the internal structure of the entry plaintext is
///   invalid. This **can** genuinely come from a legitimate payload (an encoding written by an
///   older version and read by a newer one), so the specific diagnosis is kept instead of folding
///   it into `SyncMalformed`.
pub fn open(key: &[u8; 32], record: &Record) -> Result<OpenedRecord> {
    for kind in [
        InnerRecordKind::SyncEntry,
        InnerRecordKind::SyncTombstone,
        InnerRecordKind::SyncGroup,
    ] {
        if let Ok(opened) = try_open_as(key, kind, record) {
            return Ok(opened);
        }
    }
    Err(Error::SyncAuthenticationFailed)
}

/// Tries to decrypt a record under a **specified** kind.
///
/// Authentication failure is a **normal** outcome on this path (the kind was guessed wrong), so the
/// caller must continue with the other kind instead of propagating the error.
fn try_open_as(key: &[u8; 32], kind: InnerRecordKind, record: &Record) -> Result<OpenedRecord> {
    let plaintext = crypto::open_with_key(
        key,
        kind,
        record.entry_id.as_bytes(),
        FORMAT_VERSION,
        &record.nonce,
        &record.ciphertext,
    )?;
    match kind {
        InnerRecordKind::SyncEntry => open_entry(&record.entry_id, &plaintext),
        InnerRecordKind::SyncTombstone => open_tombstone(&record.entry_id, &plaintext),
        InnerRecordKind::SyncGroup => open_group(&record.entry_id, &plaintext),
        _ => Err(Error::SyncMalformed {
            reason: "the decoding path received a non-sync record kind",
        }),
    }
}

/// Parses an **entry** plaintext that has already been decrypted and authenticated.
///
/// The plaintext is already authenticated by the AEAD, so the checks here all target "our own
/// encoding is wrong" rather than an attack.
fn open_entry(id: &EntryId, plaintext: &[u8]) -> Result<OpenedRecord> {
    if plaintext.len() < ENTRY_HEADER_LEN {
        return Err(Error::SyncTruncated);
    }
    if &plaintext[..4] != ENTRY_MAGIC {
        return Err(Error::SyncMalformed {
            reason: "the entry plaintext is missing its magic",
        });
    }
    let embedded: [u8; EntryId::LEN] = plaintext[4..4 + EntryId::LEN]
        .try_into()
        .map_err(|_| Error::SyncTruncated)?;
    if &embedded != id.as_bytes() {
        return Err(Error::SyncMalformed {
            reason: "the identifier in the entry plaintext differs from the record identifier",
        });
    }
    let len_bytes: [u8; 4] = plaintext[4 + EntryId::LEN..ENTRY_HEADER_LEN]
        .try_into()
        .map_err(|_| Error::SyncTruncated)?;
    let declared =
        usize::try_from(u32::from_be_bytes(len_bytes)).map_err(|_| Error::SyncTruncated)?;
    let body = plaintext
        .get(ENTRY_HEADER_LEN..ENTRY_HEADER_LEN + declared)
        .ok_or(Error::SyncTruncated)?;
    if plaintext.len() != ENTRY_HEADER_LEN + declared {
        return Err(Error::SyncMalformed {
            reason: "the entry plaintext holds content beyond its declared length",
        });
    }
    Ok(OpenedRecord::Entry {
        id: *id,
        entry: Box::new(crate::vault::decode_entry(body)?),
    })
}

/// Parses a **tombstone** plaintext that has already been decrypted and authenticated.
///
/// It reuses the vault-side tombstone decoder directly: the two share the same byte layout, see the
/// module documentation.
fn open_tombstone(id: &EntryId, plaintext: &[u8]) -> Result<OpenedRecord> {
    let tombstone = crate::vault::decode_tombstone(*id, plaintext)?;
    Ok(OpenedRecord::Tombstone(Box::new(tombstone)))
}

/// Parses a **group** plaintext that has already been decrypted and authenticated.
///
/// Same header layout as an entry, with its own magic: the identifier inside must equal the one
/// the record was filed under, which is what stops a group's ciphertext from being replayed under
/// another group's identifier.
fn open_group(id: &EntryId, plaintext: &[u8]) -> Result<OpenedRecord> {
    if plaintext.len() < ENTRY_HEADER_LEN {
        return Err(Error::SyncTruncated);
    }
    if &plaintext[..4] != GROUP_MAGIC {
        return Err(Error::SyncMalformed {
            reason: "the group plaintext is missing its magic",
        });
    }
    let embedded: [u8; GroupId::LEN] = plaintext[4..4 + GroupId::LEN]
        .try_into()
        .map_err(|_| Error::SyncTruncated)?;
    if &embedded != id.as_bytes() {
        return Err(Error::SyncMalformed {
            reason: "the identifier in the group plaintext differs from the record identifier",
        });
    }
    let len_bytes: [u8; 4] = plaintext[4 + GroupId::LEN..ENTRY_HEADER_LEN]
        .try_into()
        .map_err(|_| Error::SyncTruncated)?;
    let declared =
        usize::try_from(u32::from_be_bytes(len_bytes)).map_err(|_| Error::SyncTruncated)?;
    let body = plaintext
        .get(ENTRY_HEADER_LEN..ENTRY_HEADER_LEN + declared)
        .ok_or(Error::SyncTruncated)?;
    if plaintext.len() != ENTRY_HEADER_LEN + declared {
        return Err(Error::SyncMalformed {
            reason: "the group plaintext holds content beyond its declared length",
        });
    }
    Ok(OpenedRecord::Group {
        id: GroupId::from_bytes(embedded),
        group: Box::new(crate::vault::decode_group(body, FORMAT_VERSION)?),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::crypto::RecordKind;
    use crate::vault::{EntryKind, Timestamp};

    fn key() -> [u8; 32] {
        [0x5A; 32]
    }

    fn sample_entry() -> VaultEntry {
        VaultEntry::new(
            "ACME".to_owned(),
            Some("ACME 公司".to_owned()),
            "alice@example.com".to_owned(),
            crate::otp::OtpSecret::from_base32("JBSWY3DPEHPK3PXP").expect("valid secret"),
            crate::otp::Algorithm::Sha1,
            crate::otp::Digits::SIX,
            EntryKind::Totp { period: 30 },
            "工作账号".to_owned(),
            Timestamp::from(1_700_000_000_u64),
            Timestamp::from(1_700_000_100_u64),
        )
        .expect("valid entry")
    }

    #[test]
    fn an_entry_roundtrips() {
        let id = EntryId::from_bytes([1; EntryId::LEN]);
        let entry = sample_entry();
        let record = seal_entry(&key(), &id, &entry).expect("sealing succeeds");
        assert_eq!(record.entry_id, id);

        let opened = open(&key(), &record).expect("opening succeeds");
        match opened {
            OpenedRecord::Entry {
                id: got_id,
                entry: got,
            } => {
                assert_eq!(got_id, id);
                assert_eq!(
                    *got, entry,
                    "the entry content differs after the round trip"
                );
            }
            other => panic!("expected an entry, actual {other:?}"),
        }
    }

    #[test]
    fn a_tombstone_roundtrips() {
        let id = EntryId::from_bytes([2; EntryId::LEN]);
        let tombstone = Tombstone {
            entry_id: id,
            deleted_at: 1_700_000_200,
            deleted_by: Some(EntryId::from_bytes([3; EntryId::LEN])),
        };
        let record = seal_tombstone(&key(), &tombstone).expect("sealing succeeds");

        let opened = open(&key(), &record).expect("opening succeeds");
        match opened {
            OpenedRecord::Tombstone(got) => assert_eq!(
                *got, tombstone,
                "the tombstone differs after the round trip"
            ),
            other => panic!("expected a tombstone, actual {other:?}"),
        }
    }

    /// Every `deleted_by` state of a tombstone must round-trip.
    ///
    /// `deleted_by` is an `Option`, and "has a value" versus "has none" differs by a single flag
    /// byte in the encoding, so both states are exercised.
    #[test]
    fn tombstone_deleted_by_states_roundtrip() {
        let id = EntryId::from_bytes([4; EntryId::LEN]);
        for deleted_by in [None, Some(EntryId::from_bytes([5; EntryId::LEN]))] {
            let tombstone = Tombstone {
                entry_id: id,
                deleted_at: 1,
                deleted_by,
            };
            let record = seal_tombstone(&key(), &tombstone).expect("sealing succeeds");
            let opened = open(&key(), &record).expect("opening succeeds");
            match opened {
                OpenedRecord::Tombstone(got) => assert_eq!(got.deleted_by, deleted_by),
                other => panic!("expected a tombstone, actual {other:?}"),
            }
        }
    }

    /// **A wrong key must fail authentication, and must not be misread as the other kind.**
    #[test]
    fn a_wrong_key_is_rejected() {
        let id = EntryId::from_bytes([6; EntryId::LEN]);
        let record = seal_entry(&key(), &id, &sample_entry()).expect("sealing succeeds");
        let err = open(&[0x5B; 32], &record);
        assert!(
            matches!(err, Err(Error::SyncAuthenticationFailed)),
            "actual {err:?}"
        );
    }

    /// **Moving entry A's ciphertext into entry B's slot must fail.**
    ///
    /// This is the entire reason the per-record inner authentication exists: without it, a
    /// **legitimate** payload could make a receiver permanently store a record whose content and
    /// identifier do not match.
    #[test]
    fn moving_a_ciphertext_to_another_id_is_rejected() {
        let id_a = EntryId::from_bytes([7; EntryId::LEN]);
        let id_b = EntryId::from_bytes([8; EntryId::LEN]);
        let mut record = seal_entry(&key(), &id_a, &sample_entry()).expect("sealing succeeds");

        record.entry_id = id_b;
        let err = open(&key(), &record);
        assert!(
            matches!(err, Err(Error::SyncAuthenticationFailed)),
            "an entry ciphertext moved to another ID was still accepted, actual {err:?}"
        );
    }

    /// A tombstone's ciphertext must fail when it is read as an entry.
    ///
    /// This also verifies that trying both kinds introduces no **misjudgement**: a tombstone
    /// ciphertext must not authenticate on the entry path, and the normal path must yield a
    /// tombstone.
    #[test]
    fn a_tombstone_cannot_be_read_as_an_entry() {
        let id = EntryId::from_bytes([9; EntryId::LEN]);
        let tombstone = Tombstone {
            entry_id: id,
            deleted_at: 1_700_000_300,
            deleted_by: None,
        };
        let record = seal_tombstone(&key(), &tombstone).expect("sealing succeeds");
        match open(&key(), &record).expect("opening succeeds") {
            OpenedRecord::Tombstone(_) => {}
            other => panic!("a tombstone was misread as {other:?}"),
        }
    }

    /// Flipping a single ciphertext byte must be rejected, at **every** byte position.
    #[test]
    fn flipping_any_ciphertext_byte_is_rejected() {
        let id = EntryId::from_bytes([10; EntryId::LEN]);
        let record = seal_entry(&key(), &id, &sample_entry()).expect("sealing succeeds");
        for index in 0..record.ciphertext.len() {
            let mut tampered = record.clone();
            tampered.ciphertext[index] ^= 0x01;
            let err = open(&key(), &tampered);
            assert!(
                matches!(err, Err(Error::SyncAuthenticationFailed)),
                "byte {index} was flipped yet still accepted, actual {err:?}"
            );
        }
    }

    /// Tampering with the nonce must be rejected.
    ///
    /// Tested separately because the nonce is not part of the ciphertext, so the
    /// ciphertext-flipping test does not cover it.
    #[test]
    fn a_tampered_nonce_is_rejected() {
        let id = EntryId::from_bytes([11; EntryId::LEN]);
        let record = seal_entry(&key(), &id, &sample_entry()).expect("sealing succeeds");
        for index in 0..record.nonce.len() {
            let mut tampered = record.clone();
            tampered.nonce[index] ^= 0x80;
            let err = open(&key(), &tampered);
            assert!(
                matches!(err, Err(Error::SyncAuthenticationFailed)),
                "nonce byte {index} was flipped yet still accepted, actual {err:?}"
            );
        }
    }

    /// A truncated ciphertext must be rejected.
    #[test]
    fn a_truncated_ciphertext_is_rejected() {
        let id = EntryId::from_bytes([12; EntryId::LEN]);
        let record = seal_entry(&key(), &id, &sample_entry()).expect("sealing succeeds");
        for cut in 1..record.ciphertext.len().min(8) {
            let mut short = record.clone();
            short.ciphertext.truncate(record.ciphertext.len() - cut);
            assert!(
                open(&key(), &short).is_err(),
                "truncating {cut} bytes was still accepted"
            );
        }
    }

    /// Every record must use a different nonce.
    ///
    /// A 192-bit random nonce does not collide at real-world scale; the property matters because a
    /// constant nonce would only become visible as catastrophic keystream reuse once both sides
    /// hold enough data.
    #[test]
    fn nonces_differ_across_records() {
        let id = EntryId::from_bytes([13; EntryId::LEN]);
        let entry = sample_entry();
        let first = seal_entry(&key(), &id, &entry).expect("sealing succeeds");
        let second = seal_entry(&key(), &id, &entry).expect("sealing succeeds");
        assert_ne!(
            first.nonce, second.nonce,
            "two encryptions used the same nonce"
        );
        assert_ne!(
            first.ciphertext, second.ciphertext,
            "encrypting the same content twice produced the same ciphertext, randomness is broken"
        );
    }

    /// **The sync record key and the vault record key must be two different keys.**
    ///
    /// This is the core domain-separation assertion. If the two were equal, a sync payload's
    /// ciphertext could be fed in as a vault file record (the AADs might be identical byte for
    /// byte) and the AEAD would authenticate it.
    #[test]
    fn sync_and_vault_keys_are_different() {
        let master = crate::vault::MasterKey::generate().expect("randomness available");

        let sync_key = crate::sync::derive_record_key(&master).expect("derivation succeeds");
        let vault_key = crypto::entry_key(&master).expect("derivation succeeds");

        assert_ne!(
            sync_key, vault_key,
            "the sync record key and the vault record key are the same subkey, domain separation failed"
        );

        let envelope_key = crate::sync::derive_envelope_key(&master).expect("derivation succeeds");
        assert_ne!(
            sync_key, envelope_key,
            "the record key equals the envelope key"
        );
        assert_ne!(
            vault_key, envelope_key,
            "the vault key equals the envelope key"
        );

        let again = crate::sync::derive_record_key(&master).expect("derivation succeeds");
        assert_eq!(
            sync_key, again,
            "the same master key derived two different results"
        );
    }

    /// The constants themselves must not change silently.
    ///
    /// They are an external contract: changing them would make every sync payload already sent out
    /// (including the ones inside QR codes) undecryptable.
    #[test]
    fn the_domain_separation_constants_are_stable() {
        assert_eq!(
            crate::sync::HKDF_SALT_SYNC,
            *b"Qualia2FA sync salt v1 (records)",
            "the sync HKDF salt changed, every existing payload will fail to open"
        );
        assert_eq!(
            RecordKind::SyncEntry.as_byte(),
            0x81,
            "the sync entry kind byte changed"
        );
        assert_eq!(
            RecordKind::SyncTombstone.as_byte(),
            0x82,
            "the sync tombstone kind byte changed"
        );
        assert_eq!(FORMAT_VERSION, 4, "the payload format version changed");
    }

    /// **The record kind bytes of the two domains must not overlap, and each parser must refuse the
    /// other's kinds.**
    ///
    /// These are the second line of defence for domain separation (the first is the HKDF salt). It
    /// is a test rather than only a compile-time assertion in `sync.rs` because "the file parser
    /// does not accept sync kinds" is a **behavioural** assertion that a compile-time assertion
    /// cannot express: the file kinds are `0x01` / `0x02` and the sync kinds are `0x81` / `0x82`.
    #[test]
    fn the_two_domains_kinds_do_not_overlap() {
        assert!(RecordKind::from_byte(0x01).is_some());
        assert!(RecordKind::from_byte(0x02).is_some());
        assert!(
            RecordKind::from_byte(0x81).is_none(),
            "the file parser accepted the sync entry kind: a sync payload would be taken in as a vault file"
        );
        assert!(
            RecordKind::from_byte(0x82).is_none(),
            "the file parser accepted the sync tombstone kind"
        );

        assert!(RecordKind::from_sync_byte(0x81).is_some());
        assert!(RecordKind::from_sync_byte(0x82).is_some());
        assert!(
            RecordKind::from_sync_byte(0x01).is_none(),
            "the sync parser accepted the file entry kind"
        );
        assert!(RecordKind::from_sync_byte(0x02).is_none());
        assert!(RecordKind::from_sync_byte(0x00).is_none());
        assert!(RecordKind::from_sync_byte(0xFF).is_none());
    }

    /// The encoded length of a record is "fixed header + ciphertext", used by higher layers to
    /// estimate payload size.
    ///
    /// The fixed header is a 16-byte identifier, a 24-byte nonce and a 4-byte length; the ciphertext
    /// already includes the authentication tag, and there is **no** kind byte on the wire — the kind
    /// lives in the inner AAD, not in the plaintext.
    ///
    /// # This test covers the `record` side only
    ///
    /// It asserts that a record's own length equals the constant plus its own ciphertext length,
    /// which holds by construction and cannot catch a wrong constant: a single extra byte inside
    /// `RECORD_HEADER_LEN` would leave it passing. What actually pins the wire format down is
    /// `the_plaintext_record_framing_matches_encoded_len` in `sync`, which unwraps a sealed payload,
    /// reads the real plaintext byte by byte and reconciles it with `encoded_len`. This one is kept
    /// to cover the lower bound that `encoded_len` does account for the nonce and the ciphertext.
    #[test]
    fn encoded_len_matches_the_wire_format() {
        let id = EntryId::from_bytes([14; EntryId::LEN]);
        let record = seal_entry(&key(), &id, &sample_entry()).expect("sealing succeeds");
        assert_eq!(record.encoded_len(), 16 + 24 + 4 + record.ciphertext.len());
    }

    /// Entry identifiers survive the round trip byte for byte, including boundary patterns such as
    /// all zeros or all `0xFF`, which an encoding is most likely to mistake for "absent".
    #[test]
    fn entry_ids_survive_the_roundtrip_byte_for_byte() {
        for pattern in [0x00_u8, 0xFF, 0x80] {
            for position in 0..EntryId::LEN {
                let mut bytes = [0_u8; EntryId::LEN];
                bytes[position] = pattern;
                let id = EntryId::from_bytes(bytes);
                let record = seal_entry(&key(), &id, &sample_entry()).expect("sealing succeeds");
                match open(&key(), &record).expect("opening succeeds") {
                    OpenedRecord::Entry { id: got, .. } => {
                        assert_eq!(
                            got.as_bytes(),
                            &bytes,
                            "identifier {bytes:?} differs after the round trip"
                        );
                    }
                    other => panic!("expected an entry, actual {other:?}"),
                }
            }
        }
    }

    #[test]
    fn timestamp_boundaries_survive_the_roundtrip() {
        let id = EntryId::from_bytes([15; EntryId::LEN]);
        for deleted_at in [1_u64, u32::MAX.into(), u64::MAX] {
            let tombstone = Tombstone {
                entry_id: id,
                deleted_at: Timestamp::from(deleted_at),
                deleted_by: None,
            };
            let record = seal_tombstone(&key(), &tombstone).expect("sealing succeeds");
            match open(&key(), &record).expect("opening succeeds") {
                OpenedRecord::Tombstone(got) => assert_eq!(
                    got.deleted_at, deleted_at,
                    "deletion time {deleted_at} differs after the round trip"
                ),
                other => panic!("expected a tombstone, actual {other:?}"),
            }
        }
    }
}
