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

//! Union merge and adjudication.
//!
//! The merge takes the union keyed by [`EntryId`], which is the bulk of synchronization. A
//! random 128-bit identifier collides with negligible probability, so **the same ID on both
//! sides denotes the same entry** and no version vector or logical clock is needed to
//! decide which side is newer.
//!
//! The union alone cannot answer two cases, and they become a [`Conflict`]:
//!
//! | Local | Peer | Handling |
//! |---|---|---|
//! | entry | entry with the same ID, different content | **conflict**: both sides edited it, a human decides |
//! | entry | tombstone with the same ID, local entry **not modified since** | deletion accepted automatically |
//! | entry | tombstone with the same ID, local entry **modified since** | **conflict** |
//! | entry | nothing | local entry kept (the peer simply does not have it) |
//! | nothing | entry / tombstone | accepted |
//! | group | nothing | accepted |
//! | group | group with the same ID, same name and same shared relative order | nothing to do |
//! | group | group with the same ID that arranges a shared child differently | **conflict**: the user picks one whole arrangement |
//!
//! The tombstone is what makes a deletion synchronizable: in a plain union "this entry does
//! not exist here" and "this entry was deleted" are the **same observation**, both showing
//! up as "the peer does not have it". Without tombstones an offline device coming back
//! online would keep a deleted entry as "I have it, the peer does not" and the deletion
//! would be silently undone. A tombstone turns "deleted" into **a record with content**
//! that can be synchronized.
//!
//! This module never decides which side is newer on its own. Timestamps could be used to
//! guess, but that would decide for the user and deleting a 2FA entry is irreversible;
//! timestamps also come from the peer device and can be filled in freely by an attacker.
//! Apart from the two rules below, which need no human judgement, a merge where both sides
//! hold content **always** reports a conflict:
//!
//! - **Content identical field by field** → no conflict. This is the most common case: the
//!   entry was edited on one side only and the other side holds an untouched old copy.
//!   Without this rule every sync would report a pile of conflicts while nothing changed.
//! - **Local entry not modified after the tombstone's time** → deletion accepted,
//!   corresponding to "B deleted it, A never touched it": the user's intent is clear, and
//!   it is what finally lets a deletion propagate.
//!
//! A local entry newer than the tombstone **still reports a conflict**, with
//! `local_is_newer` handed to the adjudication UI as well — the single most useful fact
//! when the user decides which side to keep, but the library never picks a side from it.

use std::collections::BTreeMap;

use crate::Result;
use crate::vault::{Entry as VaultEntry, EntryId, Group, GroupChild, GroupId, Tombstone, Vault};

/// A record received from a peer, together with its identifier.
///
/// The identifier lives here rather than in [`VaultEntry`] because [`VaultEntry`]
/// deliberately carries no ID: an entry that brought its own identifier would allow two
/// contradictory identifiers within the same data. Every record in a sync payload **must**
/// carry its identifier — it is one of the AEAD associated data items and the key of the
/// union. Sealing the pair in an enum makes the state "there is an entry but its identity
/// is unknown" unrepresentable, so [`merge_into`] needs no `Result` to report a
/// self-contradictory record.
///
/// # No `Clone`
///
/// [`VaultEntry`] deliberately does not implement `Clone` (see [`crate::otp::OtpSecret`]),
/// so this enum cannot derive it either. Copying goes through
/// [`VaultEntry::duplicate`], an explicit entry point: the call site has to spell out
/// `duplicate()`, which makes "another copy of key material is made here" visible in
/// review.
#[derive(Debug, PartialEq, Eq)]
pub enum MergedRecord {
    /// A live entry.
    Entry {
        /// The identifier of the entry.
        id: EntryId,
        /// The content of the entry.
        entry: Box<VaultEntry>,
    },
    /// A tombstone (deletion record).
    Tombstone(Box<Tombstone>),
    /// A group with its ordering.
    ///
    /// The granularity is the **whole group**: its name, its position and the order of its
    /// entries travel as one value, because that is what the user arranged and what the
    /// adjudication screen shows side by side.
    Group {
        /// The identifier of the group.
        id: GroupId,
        /// The group itself.
        group: Box<Group>,
    },
}

impl MergedRecord {
    /// The 16-byte key this record is filed under.
    ///
    /// For a group that is its identifier reinterpreted, since the payload keys its records by 16
    /// opaque bytes and does not distinguish the kinds (see [`RecordSet`]).
    #[must_use]
    pub fn entry_id(&self) -> EntryId {
        match self {
            Self::Entry { id, .. } => *id,
            Self::Tombstone(tombstone) => tombstone.entry_id,
            Self::Group { id, .. } => EntryId::from_bytes(*id.as_bytes()),
        }
    }
}
/// A disagreement found in one merge that a human has to adjudicate.
///
/// The entries are copied here because a conflict is by definition "there are two different
/// versions" and the adjudication UI must see **both** sides at once. The local version is
/// copied in, and the peer's version (already in hand) is moved in.
///
/// Copying goes through [`VaultEntry::duplicate`], which is explicit and can fail. This is
/// more than a matter of style: a second copy of the same key material in memory is a
/// second exposure surface, and the copy happens **only when a disagreement really
/// exists** — in the vast majority of syncs `conflicts` is empty.
#[derive(Debug, PartialEq, Eq)]
pub struct Conflict {
    /// The entry in disagreement.
    pub entry_id: EntryId,
    /// The kind of disagreement.
    pub kind: ConflictKind,
}

impl Conflict {
    /// The group this conflict is about.
    ///
    /// An ordering conflict carries its identifier in [`Conflict::entry_id`] - the same 16-byte
    /// field every payload record is filed under, since the payload does not distinguish the
    /// kinds - and this recovers it with its meaning attached.
    #[must_use]
    pub fn group_id(&self) -> Option<GroupId> {
        match self.kind {
            ConflictKind::OrderingMismatch { .. } => {
                Some(GroupId::from_bytes(*self.entry_id.as_bytes()))
            }
            _ => None,
        }
    }
}

/// The kind of disagreement.
#[derive(Debug, PartialEq, Eq)]
pub enum ConflictKind {
    /// Both sides have this entry, with different content.
    ///
    /// The content of **both** sides is kept (rather than only a "conflict" marker): the
    /// adjudication UI has to show the account names and notes of both sides, otherwise
    /// the user cannot decide.
    EntryMismatch {
        /// The local version.
        local: Box<VaultEntry>,
        /// The version received from the peer. **Not yet** written to the local vault.
        incoming: Box<VaultEntry>,
    },
    /// Both sides have the group, and they differ in the name, the position or the ordering.
    ///
    /// **The ordering is not merged element by element.** Two devices that arranged the same
    /// entries differently hold two different sequences, and interleaving them would produce a
    /// third arrangement that neither user asked for; the user picks one of the two whole
    /// orderings (see [`crate::sync::adjudicate`]).
    OrderingMismatch {
        /// The local group.
        local: Box<Group>,
        /// The version received from the peer. **Not yet** written to the local vault.
        incoming: Box<Group>,
    },
    /// One side deleted the entry while the other still has it and it **was modified**.
    ///
    /// If the local entry was not touched after the deletion, this does not become a
    /// conflict — the deletion is accepted automatically.
    DeletionConflict {
        /// The local version.
        ///
        /// This conflict has **two directions**, and only one of them carries local content
        /// here:
        ///
        /// - **The peer sent a tombstone** (the local side has a newer live entry): the
        ///   local content is already in the vault and the adjudication UI reads it
        ///   directly, so this is `None`, saving one copy of key material.
        /// - **The peer sent a live entry** (the local side has a tombstone): the local
        ///   content is a **tombstone**, while the peer's version of the entry is already
        ///   in hand and simply moved in, so this holds the peer's version, which tells the
        ///   adjudication UI that the peer wants to restore the entry.
        ///
        /// Neither direction copies key material for display, except the one where
        /// `incoming` below is a live entry — that one has no local live entry to read.
        local: Option<Box<VaultEntry>>,
        /// The tombstone received from the peer. **Not yet** written to the local vault.
        incoming: Box<Tombstone>,
        /// The local version is later than the tombstone.
        ///
        /// This is a **hint**, not a basis for the decision: it tells the adjudication UI
        /// that this side was edited after the deletion. The library does not pick a side
        /// from it — the peer fills in the peer's own timestamps.
        local_is_newer: bool,
    },
}

/// The result of one merge.
///
/// No `Clone`: it can hold conflicts, and conflicts hold key material.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct MergeOutcome {
    /// Number of entries added.
    pub added: usize,
    /// Number of tombstones added. **Not** including the case where the local vault
    /// already had that tombstone.
    pub tombstones_added: usize,
    /// Number of deletions accepted (a local entry replaced by a tombstone).
    pub deletions_applied: usize,
    /// Number of groups added. **Not** including the case where the local vault already had that
    /// group with the same content.
    pub groups_added: usize,
    /// Number of records whose content was completely identical, so nothing was done.
    pub unchanged: usize,
    /// Disagreements that need a human to adjudicate.
    pub conflicts: Vec<Conflict>,
}

impl MergeOutcome {
    /// Whether this merge changed nothing and left no disagreement to adjudicate.
    ///
    /// Lets the UI skip "sync complete"-style messages — it is `true` when the same batch
    /// of data is synced again, which is the observable form of idempotence.
    #[must_use]
    pub fn made_no_change(&self) -> bool {
        self.added == 0
            && self.tombstones_added == 0
            && self.deletions_applied == 0
            && self.conflicts.is_empty()
    }

    /// Whether there is a disagreement waiting for adjudication.
    #[must_use]
    pub fn needs_adjudication(&self) -> bool {
        !self.conflicts.is_empty()
    }
}

/// Merges a batch of records from a peer into the local vault.
///
/// # Idempotence
///
/// Merging the same batch twice leaves `added`, `tombstones_added` and
/// `deletions_applied` at `0` on the second pass, `unchanged` at the full count, and the
/// vault contents byte-for-byte identical. The idempotence is **observable**, not merely
/// "idempotent by argument".
///
/// # Commutativity holds for the vault contents only
///
/// `merge(merge(v, a), b)` and `merge(merge(v, b), a)` leave the **same vault contents**
/// but can report **different conflict lists** (the order decides which side is treated as
/// `local`). The library does not pretend the two are equivalent: conflicts are precisely
/// the things a human has to decide, and hiding the order difference would only make the
/// adjudication UI show something other than what the user just saw.
///
/// # Errors
///
/// Structural errors other than [`crate::Error::VaultDecryptionFailed`], propagated from
/// [`VaultEntry::duplicate`], which fails only when the vault holds an entry that violates
/// the format constraints. Duplicating happens for the local side of a conflict; apart
/// from that the merge only operates on in-memory maps and cannot fail.
///
/// The `incoming` side of a conflict is **not** written: the caller has to let the user
/// adjudicate first. Writing it and letting the user revert would overwrite local data
/// before the user can react.
pub fn merge_into<'a>(
    vault: &mut Vault,
    records: impl IntoIterator<Item = &'a MergedRecord>,
) -> Result<MergeOutcome> {
    let mut outcome = MergeOutcome::default();

    // Entries and tombstones first, groups after: a group's ordering is compared against the
    // entries this device holds **once the batch has been applied**, so a group that names an
    // entry arriving in the same payload is not reported as a difference just because the two
    // records happened to be ordered that way.
    let all_records: Vec<&MergedRecord> = records.into_iter().collect();
    let mut groups: Vec<&MergedRecord> = Vec::new();
    let mut arrived: Vec<EntryId> = Vec::new();
    for record in &all_records {
        match record {
            MergedRecord::Entry { id, entry } => {
                let existed = vault.get(id).is_some() || vault.get_tombstone(id).is_some();
                merge_entry(vault, id, entry, &mut outcome)?;
                if !existed {
                    arrived.push(*id);
                }
            }
            MergedRecord::Tombstone(tombstone) => {
                merge_tombstone(vault, tombstone, &mut outcome);
            }
            MergedRecord::Group { .. } => groups.push(*record),
        }
    }
    for record in groups {
        if let MergedRecord::Group { id, group } = record {
            merge_group(vault, id, group, &mut outcome);
        }
    }
    // The same rule the file parser applies: a child no group claims belongs to the top group.
    // Without it an entry arriving in a payload that carries no group record - or whose group
    // record lost the id - would exist in the vault and appear nowhere, and an inserted group
    // would have no parent list to hang from.
    //
    // The order is the peer's: its top group lists the entries it sent in the arrangement it
    // wants, and appending them in the order the *records* happened to appear would put them
    // somewhere else - which the next sync would then report as a disagreement this merge itself
    // created. Whatever the top group does not mention follows in payload order.
    let mut claim_order: Vec<EntryId> = Vec::new();
    for record in &all_records {
        if let MergedRecord::Group { id, group } = record
            && id.is_top()
        {
            claim_order.extend(group.entry_ids());
        }
    }
    for entry_id in &arrived {
        if !claim_order.contains(entry_id) {
            claim_order.push(*entry_id);
        }
    }
    // One pass over the whole tree: it repairs duplicate references, attaches a group that
    // arrived without the parent list that names it, and places unclaimed entries - the same
    // rules the file parser applies, so a merged vault is indistinguishable from one read from
    // disk.
    vault.rebuild_tree(&claim_order, &[]);

    Ok(outcome)
}

/// Merges one group.
///
/// Three cases: the local vault has no such group, so it is inserted; it has one with the same
/// **visible** content, so nothing is done; or the two differ, which is a
/// [`ConflictKind::OrderingMismatch`] for the user.
///
/// # What counts as a disagreement
///
/// The names must match, and so must the **relative order of the children both sides list** -
/// entries and child groups alike. A child only one side lists says nothing about the other's
/// arrangement - it cannot have been placed there by the other device - so it is not a
/// disagreement: the merge keeps the local arrangement and the arriving child is placed by the
/// tree repair that follows (see [`crate::vault::Vault::rebuild_tree`]).
///
/// The stricter rule "the lists must be identical" was tried first and made **every** first sync
/// between two devices a conflict: each device has appended its own entries to the top group, so
/// the two lists differ by exactly the children the other side had never seen. What the user can
/// actually disagree about is where a child goes **relative to the others they both have**, and
/// that is what is compared here.
///
/// The consequence, stated rather than hidden: two devices that each had private entries keep
/// their own placement of those. They converge on the children they share, which is the part
/// either of them could have an opinion about.
///
/// # Moving a group can produce two conflicts
///
/// Moving a group between parents rewrites two lists - the old parent loses it and the new parent
/// gains it - and each list is a separate record, so each can be reported. That is a known cost
/// of keeping the merge at one record per group; the interface groups conflicts of the same
/// group together. Whatever order the two are adjudicated in, the tree is the same afterwards,
/// because [`crate::vault::Vault::set_children`] allows one parent per child.
///
/// Returns no `Result`: a group holds no secret material, so nothing here can fail.
fn merge_group(vault: &mut Vault, id: &GroupId, incoming: &Group, outcome: &mut MergeOutcome) {
    let Some(local) = vault.group(id) else {
        // A failure here means the identifier is already taken, which the `get` above ruled out.
        if vault.insert_group_with_id(*id, incoming.clone()).is_ok() {
            outcome.groups_added += 1;
        }
        return;
    };

    if local.name == incoming.name && !children_disagree(&local.children, &incoming.children) {
        outcome.unchanged += 1;
        return;
    }
    outcome.conflicts.push(Conflict {
        entry_id: EntryId::from_bytes(*id.as_bytes()),
        kind: ConflictKind::OrderingMismatch {
            local: Box::new(local.clone()),
            incoming: Box::new(incoming.clone()),
        },
    });
}

/// Whether two child lists place the children they **both** list differently.
///
/// Both lists are reduced to the references they have in common - the only ones either side can
/// have an opinion about - and the two reductions are compared. One child alone is always "in the
/// same order as itself", so a difference in the set of children is never reported here.
fn children_disagree(local: &[GroupChild], incoming: &[GroupChild]) -> bool {
    let shared = |list: &[GroupChild]| -> Vec<GroupChild> {
        list.iter()
            .filter(|child| incoming.contains(child))
            .copied()
            .collect()
    };
    shared(local) != shared(incoming)
}

/// Merges one live entry.
///
/// Three cases: the local vault already has a live entry with this ID (identical content →
/// `unchanged`, otherwise a [`ConflictKind::EntryMismatch`] conflict); the local vault has a
/// tombstone and no live entry, which means the entry comes from a device that has **not
/// received the deletion yet**, so it is reported as a [`ConflictKind::DeletionConflict`]
/// instead of being inserted and reviving the adjudicated deletion; and no local record at
/// all, in which case the entry is inserted. `insert_with_id` fails only when the ID already
/// exists, and both such cases are handled above, so a failure there is unreachable — the
/// result is still not `expect`-ed, so that no panic branch exists on user data.
///
/// Fails **only** because [`VaultEntry::duplicate`] failed (the local version is copied when
/// a conflict is reported).
fn merge_entry(
    vault: &mut Vault,
    id: &EntryId,
    entry: &VaultEntry,
    outcome: &mut MergeOutcome,
) -> Result<()> {
    if let Some(existing) = vault.get(id) {
        if entries_identical(existing, entry) {
            outcome.unchanged += 1;
            return Ok(());
        }
        outcome.conflicts.push(Conflict {
            entry_id: *id,
            kind: ConflictKind::EntryMismatch {
                local: Box::new(existing.duplicate()?),
                incoming: Box::new(entry.duplicate()?),
            },
        });
        return Ok(());
    }

    if let Some(tombstone) = vault.get_tombstone(id) {
        outcome.conflicts.push(Conflict {
            entry_id: *id,
            kind: ConflictKind::DeletionConflict {
                local: Some(Box::new(entry.duplicate()?)),
                incoming: Box::new(tombstone.clone()),
                local_is_newer: entry.updated_at > tombstone.deleted_at,
            },
        });
        return Ok(());
    }

    // Inserted **without** touching an ordering: the payload's group records decide the
    // arrangement, and an entry appended to the top group here would make the local top group
    // differ from the peer's copy of it, reporting a conflict that is really this insertion.
    // `merge_into` adopts whatever no group claims once everything has been applied.
    if vault.insert_parsed(*id, entry.duplicate()?).is_ok() {
        outcome.added += 1;
    }
    Ok(())
}

/// Merges one tombstone.
///
/// If the local vault already knows the tombstone, the **earlier** of the two deletion
/// times is kept: both tombstones prove that the deletion happened, and taking the earlier
/// one makes the two sides converge on the same value without refreshing the deletion time,
/// so a device deleting repeatedly cannot change an adjudicated result.
///
/// If the local side holds a live entry whose `updated_at` is not later than the deletion
/// time, the deletion is accepted: the entry is removed, the tombstone recorded and
/// `deletions_applied` incremented. `remove` runs before `record_tombstone` because
/// `Vault::record_tombstone` does **not** remove a live entry, and a live entry coexisting
/// with a tombstone is the state of an adjudication that has not finished. If the live
/// entry is newer the result is a [`ConflictKind::DeletionConflict`] with `local` set to
/// `None`: the local content stays in the vault and the adjudication UI reads it there, so
/// no key material is copied — `merge_tombstone` returns no `Result`, and copying can fail.
/// What that conflict has to display is "the local vault has a newer entry, the peer says
/// it was deleted", unlike the `EntryMismatch` branch, where both sides must be shown
/// together.
///
/// Returns no `Result`: it copies no key material (a tombstone holds no secret) and
/// therefore has nothing that can fail.
fn merge_tombstone(vault: &mut Vault, tombstone: &Tombstone, outcome: &mut MergeOutcome) {
    let id = tombstone.entry_id;

    if let Some(existing) = vault.get_tombstone(&id) {
        if tombstone.deleted_at < existing.deleted_at {
            vault.record_tombstone(tombstone.clone());
        }
        outcome.unchanged += 1;
        return;
    }

    if let Some(local) = vault.get(&id) {
        if local.updated_at <= tombstone.deleted_at {
            vault.remove(&id, tombstone.deleted_at);
            vault.record_tombstone(tombstone.clone());
            outcome.deletions_applied += 1;
            return;
        }
        outcome.conflicts.push(Conflict {
            entry_id: id,
            kind: ConflictKind::DeletionConflict {
                local: None,
                incoming: Box::new(tombstone.clone()),
                local_is_newer: true,
            },
        });
        return;
    }

    vault.record_tombstone(tombstone.clone());
    outcome.tombstones_added += 1;
}

/// Whether two entries are completely identical.
///
/// Calls [`VaultEntry`]'s `PartialEq` directly: that implementation deliberately compares
/// the secret field (the seed) **last**, so a pair of entries whose names already differ is
/// excluded at the first field and pays no constant-time comparison. See the `PartialEq` of
/// [`crate::vault::Entry`].
///
/// The wrapper exists rather than a plain `a == b` so that the call site has one place to
/// state why comparing secrets is acceptable here: whoever can perform the comparison
/// already holds both plaintexts, so an ordinary comparison is no downgrade.
fn entries_identical(a: &VaultEntry, b: &VaultEntry) -> bool {
    a == b
}

/// A container that lets callers organize records by identifier.
///
/// # Deduplication by identifier
///
/// The same `EntryId` appearing twice in one payload is **legal**: it can carry one version
/// of the entry per device. A merge can only apply one result, so which one is used has to
/// be fixed first: first-inserted wins, and whoever builds the payload is responsible for
/// putting the version it wants adopted first.
///
/// Last-inserted-wins is **not** used: that would make the order inside a payload a
/// security-relevant property (the last record decides), while the peer controls that
/// order.
///
/// # Genericity
///
/// Two places need a "record set deduplicated by identifier", with different element
/// types:
///
/// - [`MergedRecord`]: the semantic record **after decryption**, used by the merge layer.
/// - [`crate::sync::Record`]: the wire-format record that is **still encrypted**, used by
///   payload packing and parsing.
///
/// One generic container instead of two implementations is not just less code: the two
/// deduplication rules **must be identical** (both are first-inserted wins), and two
/// implementations would silently drift apart, showing up as a payload deduplicated on the
/// sending side and not on the receiving side — a failure that reproduces only on the peer.
#[derive(Debug)]
pub struct RecordSet<T> {
    /// Records indexed by identifier. A `BTreeMap` rather than a `HashMap`: the iteration
    /// order has to be deterministic.
    by_id: BTreeMap<EntryId, T>,
}

impl<T> Default for RecordSet<T> {
    fn default() -> Self {
        Self {
            by_id: BTreeMap::new(),
        }
    }
}

impl<T: HasEntryId> RecordSet<T> {
    /// An empty set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts a record; **does not overwrite** when the same ID already exists.
    ///
    /// Returns whether the record was actually inserted (`false` means this ID is already
    /// present).
    pub fn insert(&mut self, record: T) -> bool {
        let id = record.entry_id();
        if self.by_id.contains_key(&id) {
            return false;
        }
        self.by_id.insert(id, record);
        true
    }

    /// How many records there are.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    /// Whether the set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }

    /// Borrows the record for one ID.
    #[must_use]
    pub fn get(&self, id: &EntryId) -> Option<&T> {
        self.by_id.get(id)
    }

    /// Iterates in ID order.
    ///
    /// A `BTreeMap` rather than a `HashMap`: the iteration order has to be deterministic,
    /// otherwise the same payload would produce a different merge order on different
    /// devices and the order of the conflict list would follow; for the wire format it
    /// would also make two payloads with identical content produce different plaintext.
    pub fn iter(&self) -> impl Iterator<Item = (&EntryId, &T)> {
        self.by_id.iter()
    }
}

impl<'a, T> IntoIterator for &'a RecordSet<T> {
    type Item = &'a T;
    type IntoIter = std::collections::btree_map::Values<'a, EntryId, T>;

    /// Borrows every record in ID order.
    ///
    /// Borrowing rather than a `records() -> Vec<T>`: the latter requires every record to
    /// be copyable, and both element types deliberately have no `Clone` (they hold key
    /// material). Borrowing lets [`merge_into`] take a `&RecordSet` directly, without
    /// copying the key material of a whole payload just to pass it around — one sync would
    /// copy hundreds of seeds for no reason at all.
    fn into_iter(self) -> Self::IntoIter {
        self.by_id.values()
    }
}

/// A type that knows which record it is.
///
/// [`RecordSet`] uses this trait for the key of deduplication. It has this one method and
/// no more because the container needs this one thing — a wider trait would tempt the
/// container into doing what it should not (such as ordering by content, which requires
/// reading key material).
pub trait HasEntryId {
    /// Which entry this record is about.
    fn entry_id(&self) -> EntryId;
}

impl HasEntryId for MergedRecord {
    fn entry_id(&self) -> EntryId {
        match self {
            Self::Entry { id, .. } => *id,
            Self::Tombstone(tombstone) => tombstone.entry_id,
            Self::Group { id, .. } => EntryId::from_bytes(*id.as_bytes()),
        }
    }
}
