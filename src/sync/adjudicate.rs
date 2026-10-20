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

//! Applying the user's decision to one conflict.
//!
//! [`merge_into`](crate::sync::merge_into) reports a [`Conflict`] instead of deciding, because
//! the two sides disagree about content a human cares about: which version of an entry is the
//! real one, and whether an entry was deleted. This module holds the other half — what
//! "keep mine" and "take theirs" mean for each shape of conflict, and what they write into the
//! vault.
//!
//! # The decision is applied locally, and is not remembered
//!
//! Nothing here records *why* the user decided what they decided, so the same disagreement can
//! be reported again by a later sync. Applying "take theirs" does converge: a second merge of
//! the same peer payload finds the two sides identical and reports no conflict at all. Applying
//! "keep mine" cannot converge on its own — the peer still holds the other version, and its own
//! user is asked when it is their turn. A record of decisions that both sides apply without
//! asking is not implemented; see the D2 note in the project plan.
//!
//! # This layer never picks a side
//!
//! Every function here takes the [`Decision`] as an argument. Timestamps are not consulted,
//! even where they are known: the peer fills in its own, and deleting an entry is
//! irreversible, so "which side is newer" is a fact to show the user, not a rule to apply
//! behind their back.

use crate::Result;
use crate::sync::merge::{Conflict, ConflictKind};
use crate::vault::Vault;

/// What the user decided about one conflict.
///
/// The two variants are the whole vocabulary on purpose: the alternative — one "resolution"
/// value per conflict shape — would let a caller pair the wrong decision with a shape, and the
/// shapes are not symmetric ("keep" means "keep the entry" in one and "keep it deleted" in
/// another).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Keep the state of **this** device; the peer's version is discarded.
    KeepLocal,
    /// Take the peer's version, discarding the state of this device.
    TakeIncoming,
}

/// What applying a [`Decision`] did.
///
/// Returned rather than implied so that a caller can report it, and so that a test can assert
/// which of the three writes happened instead of only that the entry count changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Adjudicated {
    /// The local version stays, and nothing was written.
    KeptLocal,
    /// The peer's entry replaced the local entry of the same ID.
    TookIncomingEntry,
    /// The deletion was applied: the local entry is gone and a tombstone covers the ID.
    DeletionApplied,
    /// The entry came back: the local tombstone was dropped in favour of the peer's entry.
    Restored,
    /// The peer's ordering replaced the local one.
    TookIncomingOrdering,
}

/// Applies one user decision to the vault.
///
/// # What each shape of conflict means
///
/// | conflict | [`Decision::KeepLocal`] | [`Decision::TakeIncoming`] |
/// |---|---|---|
/// | [`ConflictKind::EntryMismatch`] | the local entry stays | the peer's entry replaces it |
/// | [`ConflictKind::DeletionConflict`] with `local: None` — the peer deleted it | the local entry stays | the entry is deleted and the tombstone recorded |
/// | [`ConflictKind::DeletionConflict`] with `local: Some(..)` — this device deleted it | it stays deleted | the peer's entry is restored and the local tombstone dropped |
/// | [`ConflictKind::OrderingMismatch`] | the local arrangement stays | the peer's whole arrangement replaces it |
///
/// The two [`ConflictKind::DeletionConflict`] directions are told apart by `local`, which is
/// the convention [`crate::sync::merge_into`] documents: the peer's record is the one that is
/// **not** yet in the vault, so the local content appears there only when the local side has
/// no live entry to read.
///
/// # Restoring an entry removes the tombstone
///
/// The tombstone is what tells every other device that the deletion happened. Keeping it
/// while the entry is alive would leave a state that is neither: the payload builder sends
/// the tombstone and not the entry (see [`crate::sync::Payload::from_vault`]), so the peer
/// would delete the entry again.
///
/// # Errors
///
/// [`crate::Error::VaultEntryNotFound`] when the conflict no longer describes the vault —
/// the local entry is gone, or the entry was already re-created. Decisions belong to the
/// merge that produced them; a stale one is refused rather than applied to whatever is there
/// now. Nothing is written when the call fails.
///
/// Structural failures are propagated from [`crate::vault::Entry::duplicate`], which copies
/// the entry that is about to be written.
pub fn adjudicate(
    vault: &mut Vault,
    conflict: &Conflict,
    decision: Decision,
) -> Result<Adjudicated> {
    match &conflict.kind {
        ConflictKind::EntryMismatch { incoming, .. } => match decision {
            Decision::KeepLocal => Ok(Adjudicated::KeptLocal),
            Decision::TakeIncoming => {
                vault.replace(conflict.entry_id, incoming.duplicate()?)?;
                Ok(Adjudicated::TookIncomingEntry)
            }
        },
        ConflictKind::OrderingMismatch { incoming, .. } => match decision {
            Decision::KeepLocal => Ok(Adjudicated::KeptLocal),
            Decision::TakeIncoming => {
                let group_id = conflict
                    .group_id()
                    .ok_or(crate::Error::VaultGroupNotFound)?;
                let group = vault
                    .group_mut(&group_id)
                    .ok_or(crate::Error::VaultGroupNotFound)?;
                *group = incoming.as_ref().clone();
                // The peer's list may name a child that this device lists elsewhere, or a group
                // that would close a cycle. Repairing the tree here keeps the invariant every
                // other operation relies on: one parent per child, no cycles, depth in range.
                vault.rebuild_tree(&[], &[]);
                Ok(Adjudicated::TookIncomingOrdering)
            }
        },
        ConflictKind::DeletionConflict {
            local, incoming, ..
        } => match (decision, local) {
            (Decision::KeepLocal, _) => Ok(Adjudicated::KeptLocal),
            (Decision::TakeIncoming, None) => {
                vault.remove(&conflict.entry_id, incoming.deleted_at);
                vault.record_tombstone(incoming.as_ref().clone());
                Ok(Adjudicated::DeletionApplied)
            }
            (Decision::TakeIncoming, Some(entry)) => {
                vault.insert_with_id(conflict.entry_id, entry.duplicate()?)?;
                vault.forget_tombstone(&conflict.entry_id);
                Ok(Adjudicated::Restored)
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::otp::{Algorithm, Digits, OtpSecret};
    use crate::sync::{MergedRecord, RecordSet, merge_into};
    use crate::vault::{
        Entry, EntryId, EntryKind, Group, GroupChild, GroupId, Timestamp, Tombstone,
    };

    /// A sample entry whose content is recognisable in an assertion.
    fn sample_entry(name: &str, updated_at: u64) -> Entry {
        Entry::new(
            name.into(),
            Some("Example".into()),
            "user@example.com".into(),
            OtpSecret::from_base32("JBSWY3DPEHPK3PXP").expect("valid Base32"),
            Algorithm::Sha1,
            Digits::SIX,
            EntryKind::Totp { period: 30 },
            String::new(),
            Timestamp::from(1_700_000_000_u64),
            Timestamp::from(updated_at),
        )
        .expect("the fields are valid")
    }

    fn entry_id(seed: u8) -> EntryId {
        EntryId::from_bytes([seed; 16])
    }

    /// A vault holding one entry under `id`.
    fn vault_with(id: EntryId, name: &str, updated_at: u64) -> Vault {
        let mut vault = Vault::new();
        vault
            .insert_with_id(id, sample_entry(name, updated_at))
            .expect("the vault is empty");
        vault
    }

    /// A vault that has deleted `id` at `deleted_at`.
    fn vault_that_deleted(id: EntryId, deleted_at: u64) -> Vault {
        let mut vault = vault_with(id, "deleted", deleted_at);
        vault.remove(&id, Timestamp::from(deleted_at));
        vault
    }

    /// The conflict a peer's differing entry produces when both sides hold the ID.
    fn mismatch(id: EntryId, local: &Entry, incoming: &Entry) -> Conflict {
        Conflict {
            entry_id: id,
            kind: ConflictKind::EntryMismatch {
                local: Box::new(local.duplicate().expect("the entry can be copied")),
                incoming: Box::new(incoming.duplicate().expect("the entry can be copied")),
            },
        }
    }

    /// The conflict a peer's entry produces when this device has deleted the ID.
    fn peer_entry_against_local_tombstone(
        id: EntryId,
        incoming: &Entry,
        deleted_at: u64,
    ) -> Conflict {
        Conflict {
            entry_id: id,
            kind: ConflictKind::DeletionConflict {
                local: Some(Box::new(
                    incoming.duplicate().expect("the entry can be copied"),
                )),
                incoming: Box::new(Tombstone {
                    entry_id: id,
                    deleted_at: Timestamp::from(deleted_at),
                    deleted_by: None,
                }),
                local_is_newer: incoming.updated_at > Timestamp::from(deleted_at),
            },
        }
    }

    /// The conflict a peer's tombstone produces when this device holds a newer entry.
    fn peer_tombstone_against_local_entry(id: EntryId, deleted_at: u64) -> Conflict {
        Conflict {
            entry_id: id,
            kind: ConflictKind::DeletionConflict {
                local: None,
                incoming: Box::new(Tombstone {
                    entry_id: id,
                    deleted_at: Timestamp::from(deleted_at),
                    deleted_by: None,
                }),
                local_is_newer: true,
            },
        }
    }

    /// Merges one peer entry again, as a later sync of the same peer would.
    fn merge_peer_entry(
        vault: &mut Vault,
        id: EntryId,
        entry: &Entry,
    ) -> crate::sync::MergeOutcome {
        let mut records = RecordSet::new();
        records.insert(MergedRecord::Entry {
            id,
            entry: Box::new(entry.duplicate().expect("the entry can be copied")),
        });
        merge_into(vault, &records).expect("the merge only copies entries")
    }

    /// Merges one peer tombstone again.
    fn merge_peer_tombstone(vault: &mut Vault, tombstone: &Tombstone) -> crate::sync::MergeOutcome {
        let mut records = RecordSet::new();
        records.insert(MergedRecord::Tombstone(Box::new(tombstone.clone())));
        merge_into(vault, &records).expect("a tombstone holds no key material to copy")
    }

    #[test]
    fn taking_the_peer_version_replaces_the_local_entry() {
        let id = entry_id(1);
        let local = sample_entry("local", 1_700_000_000);
        let peer = sample_entry("peer", 1_700_000_100);
        let mut vault = vault_with(id, "local", 1_700_000_000);

        let outcome = adjudicate(
            &mut vault,
            &mismatch(id, &local, &peer),
            Decision::TakeIncoming,
        )
        .expect("the entry is present");

        assert_eq!(outcome, Adjudicated::TookIncomingEntry);
        assert_eq!(vault.len(), 1, "replacing must not add an entry");
        let stored = vault.get(&id).expect("the entry is still there");
        assert_eq!(stored.name, "peer");
        assert_eq!(
            stored.updated_at, peer.updated_at,
            "the peer's content is adopted as it is, timestamps included"
        );

        let again = merge_peer_entry(&mut vault, id, &peer);
        assert!(
            again.conflicts.is_empty() && again.unchanged == 1,
            "the decision must close the conflict: {again:?}"
        );
    }

    #[test]
    fn keeping_the_local_version_writes_nothing() {
        let id = entry_id(2);
        let local = sample_entry("local", 1_700_000_000);
        let peer = sample_entry("peer", 1_700_000_100);
        let mut vault = vault_with(id, "local", 1_700_000_000);

        let outcome = adjudicate(
            &mut vault,
            &mismatch(id, &local, &peer),
            Decision::KeepLocal,
        )
        .expect("keeping the local version cannot fail");

        assert_eq!(outcome, Adjudicated::KeptLocal);
        assert_eq!(vault.get(&id).expect("the entry stays").name, "local");
    }

    #[test]
    fn a_peer_deletion_is_applied_with_the_peers_own_tombstone() {
        let id = entry_id(3);
        let mut vault = vault_with(id, "local", 1_700_000_200);

        let outcome = adjudicate(
            &mut vault,
            &peer_tombstone_against_local_entry(id, 1_700_000_100),
            Decision::TakeIncoming,
        )
        .expect("the entry is present");

        assert_eq!(outcome, Adjudicated::DeletionApplied);
        assert_eq!(vault.len(), 0, "the entry must be gone");
        let tombstone = vault
            .get_tombstone(&id)
            .cloned()
            .expect("the deletion is recorded");
        assert_eq!(tombstone.deleted_at, Timestamp::from(1_700_000_100_u64));
        assert_eq!(
            vault.tombstone_count(),
            1,
            "exactly one tombstone: the entry's own deletion must not be recorded twice"
        );

        let again = merge_peer_tombstone(&mut vault, &tombstone);
        assert!(
            again.conflicts.is_empty() && again.unchanged == 1,
            "the decision must close the conflict: {again:?}"
        );
    }

    #[test]
    fn keeping_the_entry_overrules_a_peer_deletion() {
        let id = entry_id(4);
        let mut vault = vault_with(id, "local", 1_700_000_200);

        let outcome = adjudicate(
            &mut vault,
            &peer_tombstone_against_local_entry(id, 1_700_000_100),
            Decision::KeepLocal,
        )
        .expect("keeping the local version cannot fail");

        assert_eq!(outcome, Adjudicated::KeptLocal);
        assert_eq!(vault.len(), 1, "the entry stays");
        assert_eq!(
            vault.tombstone_count(),
            0,
            "the peer's tombstone must not be recorded: it was not accepted"
        );
    }

    #[test]
    fn the_peer_entry_restores_an_entry_deleted_here() {
        let id = entry_id(5);
        let peer = sample_entry("peer", 1_700_000_300);
        let mut vault = vault_that_deleted(id, 1_700_000_100);

        let outcome = adjudicate(
            &mut vault,
            &peer_entry_against_local_tombstone(id, &peer, 1_700_000_100),
            Decision::TakeIncoming,
        )
        .expect("nothing is copied from the vault here");

        assert_eq!(outcome, Adjudicated::Restored);
        assert_eq!(vault.get(&id).expect("the entry is back").name, "peer");
        assert_eq!(
            vault.tombstone_count(),
            0,
            "a tombstone next to a live entry would be sent on its own and delete the entry again"
        );

        let again = merge_peer_entry(&mut vault, id, &peer);
        assert!(
            again.conflicts.is_empty() && again.unchanged == 1,
            "the decision must close the conflict: {again:?}"
        );
    }

    #[test]
    fn confirming_a_deletion_here_drops_the_peer_entry() {
        let id = entry_id(6);
        let peer = sample_entry("peer", 1_700_000_300);
        let mut vault = vault_that_deleted(id, 1_700_000_100);

        let outcome = adjudicate(
            &mut vault,
            &peer_entry_against_local_tombstone(id, &peer, 1_700_000_100),
            Decision::KeepLocal,
        )
        .expect("keeping the local version cannot fail");

        assert_eq!(outcome, Adjudicated::KeptLocal);
        assert!(vault.get(&id).is_none(), "the entry stays deleted");
        assert!(
            vault.get_tombstone(&id).is_some(),
            "the deletion is still recorded, so it keeps travelling"
        );
    }

    #[test]
    fn a_decision_for_an_entry_that_no_longer_exists_is_refused() {
        let id = entry_id(7);
        let local = sample_entry("local", 1_700_000_000);
        let peer = sample_entry("peer", 1_700_000_100);
        let mut vault = Vault::new();

        let result = adjudicate(
            &mut vault,
            &mismatch(id, &local, &peer),
            Decision::TakeIncoming,
        );

        assert!(
            matches!(result, Err(crate::Error::VaultEntryNotFound)),
            "actual {result:?}"
        );
        assert_eq!(vault.len(), 0, "a refused decision must write nothing");
    }

    /// A vault holding `ids` in the top group, in the order given.
    fn vault_with_ordering(ids: &[EntryId]) -> Vault {
        let mut vault = Vault::new();
        for (index, id) in ids.iter().enumerate() {
            vault
                .insert_with_id(*id, sample_entry(&format!("entry {index}"), 1_700_000_000))
                .expect("the vault is empty");
        }
        vault
            .set_ordering(&GroupId::TOP, ids.to_vec())
            .expect("the identifiers exist");
        vault
    }

    /// A group record from a peer, filed under the top group's identifier.
    fn incoming_top_group(entry_ids: Vec<EntryId>) -> MergedRecord {
        MergedRecord::Group {
            id: GroupId::TOP,
            group: Box::new(
                Group::top(entry_ids.into_iter().map(GroupChild::Entry).collect())
                    .expect("the list is valid"),
            ),
        }
    }

    /// A group the peer has and this device does not becomes a group here.
    #[test]
    fn a_group_only_the_peer_has_is_added() {
        let mut vault = Vault::new();
        let work = GroupId::generate().expect("OS randomness available");

        let outcome = merge_into(
            &mut vault,
            &[MergedRecord::Group {
                id: work,
                group: Box::new(
                    Group::new("Work".to_owned(), Vec::new()).expect("the group is valid"),
                ),
            }],
        )
        .expect("merging a group cannot fail");

        assert_eq!(outcome.groups_added, 1);
        assert!(outcome.conflicts.is_empty());
        assert_eq!(
            vault.group(&work).map(|group| group.name.as_str()),
            Some("Work")
        );
    }

    /// Two arrangements that only differ in **which entries they mention** are not a
    /// disagreement: neither device can have placed an entry it has never seen.
    ///
    /// This is the shape every first sync between two devices has - each appended its own entries
    /// to the top group - and reporting it would make the user adjudicate something no one
    /// disagrees about.
    #[test]
    fn orderings_that_differ_only_in_their_entries_agree() {
        let shared = entry_id(20);
        let mut vault = vault_with_ordering(&[shared, entry_id(21)]);

        let outcome = merge_into(&mut vault, &[incoming_top_group(vec![shared])])
            .expect("merging cannot fail");

        assert!(
            outcome.conflicts.is_empty(),
            "the peer lists a subset of what this device has, in the same relative order"
        );
        assert_eq!(outcome.unchanged, 1);
    }

    /// The peer's arrangement of the entries it sends is reproduced, not overridden by the order
    /// the records happened to arrive in.
    #[test]
    fn arriving_entries_are_placed_in_the_peer_order() {
        let first = entry_id(30);
        let second = entry_id(31);
        let mut vault = Vault::new();

        let outcome = merge_into(
            &mut vault,
            &[
                MergedRecord::Entry {
                    id: first,
                    entry: Box::new(sample_entry("first", 1_700_000_000)),
                },
                MergedRecord::Entry {
                    id: second,
                    entry: Box::new(sample_entry("second", 1_700_000_000)),
                },
                // The peer's ordering puts the *second* identifier first; the identifiers sort
                // the other way, so an implementation that followed the record order would fail
                // here.
                incoming_top_group(vec![second, first]),
            ],
        )
        .expect("merging cannot fail");

        assert_eq!(outcome.added, 2);
        assert!(outcome.conflicts.is_empty(), "actual {outcome:?}");
        assert_eq!(
            vault.ordering(&GroupId::TOP),
            Some(vec![second, first]),
            "the arrangement is the peer's"
        );
    }

    /// Two arrangements that disagree about the relative order of a shared entry are a conflict,
    /// and the user's choice replaces the whole ordering.
    #[test]
    fn a_disagreeing_ordering_is_adjudicated_as_a_whole() {
        let first = entry_id(40);
        let second = entry_id(41);
        let mut vault = vault_with_ordering(&[first, second]);

        let outcome = merge_into(&mut vault, &[incoming_top_group(vec![second, first])])
            .expect("merging cannot fail");

        let conflict = outcome
            .conflicts
            .first()
            .expect("the two arrangements disagree");
        assert_eq!(conflict.group_id(), Some(GroupId::TOP));
        assert!(
            matches!(conflict.kind, ConflictKind::OrderingMismatch { .. }),
            "actual {:?}",
            conflict.kind
        );
        assert_eq!(
            vault.ordering(&GroupId::TOP),
            Some(vec![first, second]),
            "a conflict writes nothing until it is adjudicated"
        );

        assert_eq!(
            adjudicate(&mut vault, conflict, Decision::KeepLocal).expect("keeping cannot fail"),
            Adjudicated::KeptLocal
        );
        assert_eq!(vault.ordering(&GroupId::TOP), Some(vec![first, second]));

        assert_eq!(
            adjudicate(&mut vault, conflict, Decision::TakeIncoming)
                .expect("taking the peer's arrangement cannot fail"),
            Adjudicated::TookIncomingOrdering
        );
        assert_eq!(
            vault.ordering(&GroupId::TOP),
            Some(vec![second, first]),
            "the whole arrangement was replaced"
        );
    }

    /// The same merge applied twice changes nothing the second time.
    #[test]
    fn merging_the_same_group_twice_changes_nothing() {
        let first = entry_id(50);
        let second = entry_id(51);
        let mut vault = vault_with_ordering(&[first, second]);
        let records = [incoming_top_group(vec![first, second])];

        let outcome = merge_into(&mut vault, &records).expect("merging cannot fail");
        assert_eq!(outcome.unchanged, 1);
        assert!(outcome.made_no_change());

        let again = merge_into(&mut vault, &records).expect("merging cannot fail");
        assert!(
            again.made_no_change(),
            "the second merge reports changes: {again:?}"
        );
    }
}
