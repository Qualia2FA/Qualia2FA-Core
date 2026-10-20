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

//! Property-based tests for the vault file.
//!
//! The generators cover arbitrary entry sets of up to 12 entries (some of them deleted, so
//! tombstones are present), arbitrary text fields including multi-byte characters, arbitrary
//! secrets of up to 64 bytes, and arbitrary byte streams of up to 512 bytes.
//!
//! Core properties:
//!
//! 1. **Round-trip fidelity**: any entry set written to disk and read back keeps every field
//!    of every entry and tombstone.
//! 2. **Tampering is detected**: changing any byte of the file makes parsing fail.
//! 3. **Truncation yields no data**: truncating the file at any position never lets an entry
//!    or a tombstone survive.
//! 4. **Parsing never panics**: any byte stream is acceptable input.
//! 5. **The format is an external contract**: magic, version, readable versions and the
//!    key, nonce and tag lengths do not drift with the implementation.
//!
//! Note: `prop_assert!` stringifies its whole expression into a format string, so a
//! `matches!(..)` pattern containing braces must be bound to a `bool` first.

use proptest::prelude::*;
use qualia2fa_core::ExposeSecret;
use qualia2fa_core::otp::{Algorithm, Digits, OtpSecret};
use qualia2fa_core::vault::{
    self, Entry, EntryId, EntryKind, FORMAT_VERSION, MAGIC, MasterKey, READABLE_VERSIONS,
    Tombstone, Vault, VaultFile,
};

/// Generates an arbitrary byte secret.
///
/// The upper bound is 64 bytes: a real seed is at most 64 bytes (the HMAC-SHA512 block size
/// recommended by RFC 4226), and anything larger adds no coverage while slowing every
/// iteration down.
fn arb_secret_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 1..=64)
}

/// Generates an arbitrary UTF-8 text field.
///
/// Non-ASCII (multi-byte characters such as Chinese and emoji) and ASCII boundary characters
/// are included on purpose: field length limits are counted in **bytes**, and length or
/// truncation errors show up on multi-byte characters.
///
/// Code points are drawn from `0..0x80`, `0x80..0xD800` and `0xE000..0x2FFFF`; the surrogate
/// range `0xD800..0xE000` is excluded because `char::from_u32` rejects it.
fn arb_text() -> impl Strategy<Value = String> {
    prop::collection::vec(
        prop_oneof![0_u32..0x80, 0x80_u32..0xD800, 0xE000_u32..0x2FFFF,],
        0..=24,
    )
    .prop_map(|codes| codes.into_iter().filter_map(char::from_u32).collect())
}

/// Generates an arbitrary entry kind, PIN-carrying ones included.
///
/// The PIN strategies are deliberately narrow (digits only, bounded length): this property is
/// about the storage format carrying whatever the model can hold, not about which PINs users
/// choose.
fn arb_kind() -> impl Strategy<Value = EntryKind> {
    prop_oneof![
        (1_u64..=604_800).prop_map(|period| EntryKind::Totp { period }),
        any::<u64>().prop_map(|counter| EntryKind::Hotp { counter }),
        ((1_u64..=3_600), prop::option::of("[0-9]{0,8}")).prop_map(|(period, pin)| {
            EntryKind::Motp {
                period,
                pin: pin.map(qualia2fa_core::motp::MotpPin::new),
            }
        }),
        ((1_u64..=3_600), prop::option::of("[0-9]{0,16}")).prop_map(|(period, pin)| {
            EntryKind::Yandex {
                period,
                pin: pin.map(qualia2fa_core::yaotp::YandexPin::new),
            }
        }),
        prop::bool::ANY.prop_map(|_| EntryKind::Steam),
    ]
}

/// Generates an entry that satisfies every invariant.
///
/// [`Entry::new`] rejects an empty secret, `period == 0` and over-long fields; illegal values
/// would be stopped at that one layer and never reach the persistence logic, which would
/// dilute the effective cases. The rejection logic itself is covered by the dedicated unit
/// tests in `src/vault/entry.rs`.
fn arb_entry() -> impl Strategy<Value = Entry> {
    (
        arb_text(),
        prop::option::of(arb_text()),
        arb_text(),
        arb_secret_bytes(),
        prop_oneof![
            Just(Algorithm::Sha1),
            Just(Algorithm::Sha256),
            Just(Algorithm::Sha512)
        ],
        prop_oneof![Just(Digits::SIX), Just(Digits::SEVEN), Just(Digits::EIGHT)],
        arb_kind(),
        arb_text(),
        any::<u64>(),
        any::<u64>(),
    )
        .prop_map(
            |(
                name,
                issuer,
                account,
                secret_bytes,
                algorithm,
                digits,
                kind,
                note,
                created_at,
                updated_at,
            )| {
                Entry::new(
                    name,
                    issuer,
                    account,
                    OtpSecret::from_bytes(secret_bytes).expect("the strategy guarantees non-empty"),
                    algorithm,
                    digits,
                    kind,
                    note,
                    created_at,
                    updated_at,
                )
                .expect("the strategy guarantees valid fields")
            },
        )
}

/// Generates an entry set.
///
/// The upper bound is 12: enough to cover structural questions such as multiple records and
/// their order, while keeping one case in the tens of milliseconds — every case runs many
/// times, and a slow case lowers the number of rounds covered.
fn arb_entries() -> impl Strategy<Value = Vec<Entry>> {
    prop::collection::vec(arb_entry(), 0..=12)
}

/// Generates a vault: an entry set with some of it deleted.
///
/// The returned id list holds the entries that are still alive, for use in assertions.
fn arb_vault() -> impl Strategy<Value = (Vault, MasterKey, Vec<EntryId>)> {
    (arb_entries(), prop::collection::vec(any::<bool>(), 0..=12)).prop_map(|(entries, deletes)| {
        let mut vault = Vault::new();
        let mut live = Vec::new();
        for (index, entry) in entries.into_iter().enumerate() {
            let id = vault.insert(entry).expect("OS random source is available");
            if deletes.get(index).copied().unwrap_or(false) {
                vault.remove(&id, 1_700_000_000);
            } else {
                live.push(id);
            }
        }
        let master = MasterKey::generate().expect("OS random source is available");
        (vault, master, live)
    })
}

/// Asserts that two entries are equal in **every** field.
///
/// `Entry` does not derive `PartialEq` because its `secret` field is [`OtpSecret`], which
/// deliberately does not implement `PartialEq`: deriving it would make "compare two seeds with
/// `==`" a casual operation, and that comparison is not constant time. The fields are therefore
/// compared one by one, with the secret compared in its Base32 form — test-only, taking part in
/// no authentication decision.
fn assert_entry_eq(a: &Entry, b: &Entry) {
    assert_eq!(a.name, b.name, "name");
    assert_eq!(a.issuer, b.issuer, "issuer");
    assert_eq!(a.account, b.account, "account");
    assert_eq!(
        a.secret.to_base32(),
        b.secret.to_base32(),
        "secret (Base32 form)"
    );
    assert_eq!(a.algorithm, b.algorithm, "algorithm");
    assert_eq!(a.digits, b.digits, "digits");
    assert_eq!(a.kind, b.kind, "kind");
    assert_eq!(a.note, b.note, "note");
    assert_eq!(a.created_at, b.created_at, "created_at");
    assert_eq!(a.updated_at, b.updated_at, "updated_at");
}

/// Copies a master key.
///
/// `MasterKey` deliberately does not implement `Clone`; going through its bytes keeps the copy
/// visible in the code instead of hiding it behind a silent `.clone()`.
fn clone_key(master: &MasterKey) -> MasterKey {
    MasterKey::from_bytes(vault::master_key_to_bytes(master)).expect("the length is correct")
}

proptest! {
    /// **Core property 1**: any entry set written to disk and read back keeps every field.
    #[test]
    fn roundtrip_preserves_every_entry((vault, master, live_ids) in arb_vault()) {
        let mut file = VaultFile::with_master_key(clone_key(&master));

        let mut expected: Vec<(EntryId, String)> = Vec::new();
        for (id, entry) in vault.iter() {
            expected.push((*id, entry.name.clone()));
            file.vault_mut()
                .insert_with_id(*id, clone_entry(entry))
                .expect("the strategy generates distinct IDs");
        }
        for tombstone in vault.iter_tombstones().map(|(_, t)| t) {
            file.vault_mut().record_tombstone(Tombstone {
                entry_id: tombstone.entry_id,
                deleted_at: tombstone.deleted_at,
                deleted_by: tombstone.deleted_by,
            });
        }
        expected.sort_by_key(|(id, _)| *id);
        let expected_tombstones = vault.tombstone_count();

        let bytes = file.serialize().expect("serializable");
        let reopened = VaultFile::parse(clone_key(&master), &bytes).expect("parsable");

        prop_assert_eq!(reopened.vault().len(), expected.len(), "the entry count changed");
        prop_assert_eq!(
            reopened.vault().tombstone_count(),
            expected_tombstones,
            "the tombstone count changed"
        );

        let mut actual: Vec<(EntryId, String)> = reopened
            .vault()
            .iter()
            .map(|(id, entry)| (*id, entry.name.clone()))
            .collect();
        actual.sort_by_key(|(id, _)| *id);
        prop_assert_eq!(&actual, &expected, "the set of entry IDs or names changed");

        for (id, _) in &expected {
            let before = vault.get(id).expect("the original entry exists");
            let after = reopened.vault().get(id).expect("the entry read back exists");
            assert_entry_eq(before, after);
        }

        for id in &live_ids {
            prop_assert!(reopened.vault().get(id).is_some(), "a surviving entry was lost");
        }
    }

    /// **Core property 2**: changing any single byte of the file makes parsing fail, or leaves
    /// the contents **identical**.
    ///
    /// This is the threat model in which an attacker can read and write the file freely.
    /// Accepting a file with one changed byte and *different* content would be silent data
    /// corruption.
    ///
    /// The "or identical" half is not a loophole: the format version byte is the one byte whose
    /// change can survive parsing, because versions 2 and 3 have the same layout. For a file
    /// with records the version takes part in every record's AAD, so such a flip fails
    /// authentication; for an **empty** vault there is nothing to authenticate, and the result
    /// is another valid empty vault. Asserting failure there would misreport a correct parse as
    /// a defect — the same reasoning as core property 3 below.
    #[test]
    fn any_single_byte_flip_is_detected((vault, master, _live) in arb_vault(), flip_seed in any::<prop::sample::Index>()) {
        let mut file = VaultFile::with_master_key(clone_key(&master));
        for (id, entry) in vault.iter() {
            file.vault_mut().insert_with_id(*id, clone_entry(entry)).expect("IDs are distinct");
        }
        for (id, tombstone) in vault.iter_tombstones() {
            file.vault_mut().record_tombstone(Tombstone {
                entry_id: *id,
                deleted_at: tombstone.deleted_at,
                deleted_by: tombstone.deleted_by,
            });
        }
        let bytes = file.serialize().expect("serializable");
        prop_assume!(!bytes.is_empty());

        let index = flip_seed.index(bytes.len());
        let mut tampered = bytes.clone();
        tampered[index] ^= 0x01;

        match VaultFile::parse(clone_key(&master), &tampered) {
            Err(_) => {}
            Ok(parsed) => {
                prop_assert!(
                    parsed.vault().is_empty()
                        && parsed.vault().tombstone_count() == 0
                        && vault.is_empty()
                        && vault.tombstone_count() == 0,
                    "byte {} was flipped ({:#04x} -> {:#04x}) and the file was still accepted \
                     with different contents",
                    index,
                    bytes[index],
                    tampered[index]
                );
            }
        }
    }

    /// **Core property 3**: truncation must not let **any data** pass verification.
    ///
    /// The assertion is "no entry survives", not "parsing always fails": an **empty** vault is
    /// just the 14-byte file header, so truncating a file to 14 bytes (that is, to itself) is a
    /// legal empty vault, and asserting failure would misreport it as a defect.
    ///
    /// What must hold is that **no data sneaks through by truncation**: if a truncated file
    /// still parses, it must hold no entry and no tombstone. The AEAD tag covers the whole
    /// ciphertext, so cutting off any part of it fails authentication — including cutting off
    /// part of the last record.
    #[test]
    fn truncation_never_yields_data((vault, master, _live) in arb_vault(), cut_seed in any::<prop::sample::Index>()) {
        let mut file = VaultFile::with_master_key(clone_key(&master));
        for (id, entry) in vault.iter() {
            file.vault_mut()
                .insert_with_id(*id, clone_entry(entry))
                .expect("the strategy generates distinct IDs");
        }
        for tombstone in vault.iter_tombstones().map(|(_, t)| t) {
            file.vault_mut().record_tombstone(Tombstone {
                entry_id: tombstone.entry_id,
                deleted_at: tombstone.deleted_at,
                deleted_by: tombstone.deleted_by,
            });
        }
        let bytes = file.serialize().expect("serializable");
        prop_assume!(!bytes.is_empty());

        let cut = cut_seed.index(bytes.len());
        match VaultFile::parse(clone_key(&master), &bytes[..cut]) {
            Err(_) => {}
            Ok(parsed) => {
                prop_assert_eq!(
                    parsed.vault().len(),
                    0,
                    "an entry survived truncation to {} bytes",
                    cut
                );
                prop_assert_eq!(
                    parsed.vault().tombstone_count(),
                    0,
                    "a tombstone survived truncation to {} bytes",
                    cut
                );
            }
        }
    }

    /// Empty input must be rejected — it does not even hold a file header, so it cannot be a
    /// legal truncation of anything.
    #[test]
    fn empty_input_is_always_rejected(_seed in any::<u64>()) {
        let master = MasterKey::generate().expect("OS random source is available");
        prop_assert!(VaultFile::parse(master, &[]).is_err());
    }

    /// Any byte stream is acceptable input — the parser only ever returns an error, never
    /// panics.
    #[test]
    fn parsing_arbitrary_bytes_never_panics(data in prop::collection::vec(any::<u8>(), 0..=512)) {
        let master = MasterKey::generate().expect("OS random source is available");
        let _ = VaultFile::parse(master, &data);
    }

    /// **Forward compatibility**: an unknown top-level structure must be rejected, not
    /// misinterpreted.
    ///
    /// Both the magic and the version number take part in the decision, so renaming an
    /// unrelated file to `.q2fa` does not get it read as a vault.
    ///
    /// Versions are generated from `FORMAT_VERSION + 1` upwards: the current version and every
    /// readable older version must be **accepted** (that is the promise that a user's old files
    /// still open), so they cannot serve as samples of an unknown version.
    #[test]
    fn wrong_magic_or_version_is_rejected(
        (vault, master, _live) in arb_vault(),
        magic_flip in any::<bool>(),
        version in (FORMAT_VERSION + 1)..=255,
    ) {
        let mut file = VaultFile::with_master_key(clone_key(&master));
        for (id, entry) in vault.iter() {
            file.vault_mut().insert_with_id(*id, clone_entry(entry)).expect("IDs are distinct");
        }
        let mut bytes = file.serialize().expect("serializable");

        if magic_flip {
            bytes[0] ^= 0xFF;
            let is_bad_magic = matches!(
                VaultFile::parse(clone_key(&master), &bytes),
                Err(qualia2fa_core::Error::VaultBadMagic)
            );
            prop_assert!(is_bad_magic, "the magic was corrupted but not rejected");
        } else {
            bytes[8] = version;
            let is_unsupported = matches!(
                VaultFile::parse(clone_key(&master), &bytes),
                Err(qualia2fa_core::Error::VaultUnsupportedVersion { .. })
            );
            prop_assert!(is_unsupported, "version {} was not rejected", version);
        }
    }

    /// A different master key must not open the file — including one that differs in a single
    /// bit.
    ///
    /// This rules out an implementation error in which the key never really enters the
    /// encryption.
    #[test]
    fn a_different_master_key_cannot_open(
        (vault, master, _live) in arb_vault(),
        delta in 1_u8..=255,
    ) {
        prop_assume!(!vault.is_empty());
        let mut file = VaultFile::with_master_key(clone_key(&master));
        for (id, entry) in vault.iter() {
            file.vault_mut().insert_with_id(*id, clone_entry(entry)).expect("IDs are distinct");
        }
        let bytes = file.serialize().expect("serializable");

        let mut other = vault::master_key_to_bytes(&master).expose_secret().to_vec();
        other[0] ^= delta;
        let other = MasterKey::from_bytes(other.into()).expect("the length is correct");

        prop_assert!(VaultFile::parse(other, &bytes).is_err(), "a different key must not open it");
    }
}

/// Copies an entry.
///
/// `Entry` implements neither `Clone` nor a public way of reading a PIN back out, so the copy
/// goes through the storage codec, which is the same path the sync merge uses. **Test-only**:
/// on a production path, copying a seed should be an explicit and justified operation.
fn clone_entry(entry: &Entry) -> Entry {
    entry.duplicate().expect("the entry can be copied")
}

/// The file header layout is an external contract: these assertions do not drift with the
/// implementation.
///
/// They live in the property-test file because what they constrain is the **format** (an
/// external promise) rather than the implementation detail of one function — a published
/// format cannot change.
#[test]
fn file_format_constants_are_stable() {
    assert_eq!(MAGIC, b"Q2FAVLT\0", "the magic is an external contract");
    assert_eq!(
        FORMAT_VERSION, 4,
        "the version takes part in the AAD, so changing it makes every old file unopenable"
    );
    assert_eq!(
        READABLE_VERSIONS,
        &[1, 2, 3, 4],
        "readable versions only grow: removing one would suddenly make users' old files unopenable"
    );
    assert_eq!(vault::MASTER_KEY_LEN, 32, "master key length");
    assert_eq!(vault::NONCE_LEN, 24, "XChaCha20 nonce length");
    assert_eq!(vault::TAG_LEN, 16, "Poly1305 tag length");
    assert_eq!(vault::KEY_CHECK_LEN, 32, "master key check value length");
    assert_eq!(EntryId::LEN, 16, "128-bit entry identifier");
}
