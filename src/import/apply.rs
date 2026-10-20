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

//! Comparing an import against a vault, and applying it.
//!
//! The reader answers what a file says. This module answers the question the user actually faces:
//! **what does this file mean for the vault I already have?** It is the second half of an import,
//! and it is separated from the reader because it is the only half that needs the vault.
//!
//! # Three outcomes, and only one of them asks
//!
//! | The vault | The entry | Outcome |
//! |---|---|---|
//! | holds the same entry | identical in every field the user can see | **skipped**, counted |
//! | holds an entry with the same secret | different in some field | the **user** decides |
//! | holds nothing with that secret | - | added |
//!
//! "The same secret" is the identity that matters here: an account can be renamed, re-issued with
//! a different digit count, moved between groups, and it is still the same second factor. Two rows
//! with the same secret are therefore one account seen twice, and a human is the only one who can
//! say which of the two is the one they want - so a differing entry is never resolved
//! automatically, in either direction.
//!
//! Timestamps are deliberately **not** part of "identical": they say when a copy was written, not
//! which account it is, and treating them as content would turn every re-import of the same file
//! into a question.
//!
//! # Applying changes nothing without an answer
//!
//! [`apply`] adds entries, and only ever replaces one where the caller passed an explicit
//! [`Choice::Replace`]. A missing answer means "add", never "overwrite": an import that loses a
//! note the user wrote is worse than an import that leaves a duplicate they can delete.
//!
//! # Favourites become an arrangement
//!
//! The export marks entries as favourites and this model has no such field, so the mark becomes
//! the only thing it can honestly become: **order**. Within each group, the arriving favourites
//! are placed before the arriving non-favourites, each in the order the export listed them, and
//! the entries already in the group keep their places at the front. A group an arrival names takes
//! it out of the top group, which is what membership means here.

use std::collections::BTreeMap;
use std::collections::HashMap;

use crate::Result;
use crate::import::{ImportReport, ImportedEntry};
use crate::vault::{Entry, EntryId, GroupId, Vault};

/// A field in which an imported entry differs from the one the vault holds.
///
/// Listed one by one rather than as "something differs" so that the interface can say **what**
/// would change: "the name and the note" is a decision a user can make, "an entry differs" is not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Difference {
    /// The display name.
    Name,
    /// The issuer.
    Issuer,
    /// The account name.
    Account,
    /// The free-form note.
    Note,
    /// The hash algorithm.
    Algorithm,
    /// The digit count.
    Digits,
    /// The kind, which carries the time step, the counter and any PIN.
    Kind,
}

/// What the vault holds that relates to one imported entry.
#[derive(Debug, Clone)]
pub struct Match {
    /// Where the entry was in the export.
    pub position: usize,
    /// Entries in the vault that use the same secret, the closest match first.
    ///
    /// More than one is possible and is not an error: a user can have imported the same account
    /// twice before, and the interface may then offer to replace either of them.
    pub existing: Vec<EntryId>,
    /// Whether the vault already holds this entry, in every field the user can see.
    pub identical: bool,
    /// The fields that differ from the closest match, empty when identical or unmatched.
    pub differences: Vec<Difference>,
}

impl Match {
    /// Whether nothing in the vault uses this secret.
    #[must_use]
    pub fn is_new(&self) -> bool {
        self.existing.is_empty()
    }
}

/// Compares every entry of a report against a vault.
///
/// The result is in the order of [`ImportReport::entries`], one entry per imported entry.
#[must_use]
pub fn compare(report: &ImportReport, vault: &Vault) -> Vec<Match> {
    report
        .entries
        .iter()
        .map(|imported| match_entry(imported, vault))
        .collect()
}

/// Compares one imported entry against a vault.
fn match_entry(imported: &ImportedEntry, vault: &Vault) -> Match {
    let mut existing = Vec::new();
    for (id, entry) in vault.iter() {
        if entry.secret == imported.entry.secret {
            existing.push(*id);
        }
    }

    let identical = existing.iter().any(|id| {
        vault
            .get(id)
            .is_some_and(|entry| same_content(entry, &imported.entry))
    });
    let differences = existing
        .first()
        .and_then(|id| vault.get(id))
        .map_or_else(Vec::new, |entry| differences(entry, &imported.entry));

    Match {
        position: imported.position,
        existing,
        identical,
        differences,
    }
}

/// Whether two entries are the same entry as far as a user is concerned.
///
/// Every field counts except the two timestamps: see the module documentation.
#[must_use]
pub fn same_content(left: &Entry, right: &Entry) -> bool {
    left.name == right.name
        && left.issuer == right.issuer
        && left.account == right.account
        && left.note == right.note
        && left.algorithm == right.algorithm
        && left.digits == right.digits
        && left.kind == right.kind
        && left.secret == right.secret
}

/// The fields in which two entries with the same secret differ.
fn differences(existing: &Entry, imported: &Entry) -> Vec<Difference> {
    let mut found = Vec::new();
    if existing.name != imported.name {
        found.push(Difference::Name);
    }
    if existing.issuer != imported.issuer {
        found.push(Difference::Issuer);
    }
    if existing.account != imported.account {
        found.push(Difference::Account);
    }
    if existing.note != imported.note {
        found.push(Difference::Note);
    }
    if existing.algorithm != imported.algorithm {
        found.push(Difference::Algorithm);
    }
    if existing.digits != imported.digits {
        found.push(Difference::Digits);
    }
    if existing.kind != imported.kind {
        found.push(Difference::Kind);
    }
    found
}

/// What to do with one imported entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Choice {
    /// Add it, leaving whatever the vault holds alone.
    Add,
    /// Change nothing: the vault already holds it.
    Skip,
    /// Put the imported version in place of the entry with this identifier.
    ///
    /// The identifier stays, so the entry keeps its group and its place in the ordering: what the
    /// user is choosing is which **content** is right, not which row it is.
    Replace(EntryId),
    /// Add it and keep the existing entry as well.
    KeepBoth,
}

/// What an applied import did.
#[derive(Debug, Default, Clone)]
pub struct Applied {
    /// Entries added, by the identifier they received.
    pub added: Vec<EntryId>,
    /// Entries whose content was replaced, by the identifier they already had.
    pub replaced: Vec<EntryId>,
    /// Entries left alone because the vault already held them.
    pub skipped: usize,
    /// Groups created from the export.
    pub groups_created: Vec<GroupId>,
    /// Groups the export named that the vault already had.
    pub groups_existing: Vec<GroupId>,
}

impl Applied {
    /// Whether the import changed nothing at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.replaced.is_empty() && self.skipped == 0
    }
}

/// Applies a report to a vault.
///
/// `choices` holds the answers for the entries the user was asked about, keyed by the position the
/// entry had in the export. An entry with no answer is **added** unless the vault already holds it
/// exactly, in which case it is skipped.
///
/// # Errors
///
/// [`crate::Error::VaultEntryNotFound`] when an answer names an entry the vault does not hold, and
/// the errors the vault itself reports for a name that is too long or an identifier that is taken.
pub fn apply(
    vault: &mut Vault,
    report: &ImportReport,
    choices: &HashMap<usize, Choice>,
) -> Result<Applied> {
    let mut applied = Applied::default();

    // Groups first, so that an arriving entry can be placed in the group it names.
    for group in &report.groups {
        if vault.group(&group.id).is_some() {
            applied.groups_existing.push(group.id);
            continue;
        }
        vault.create_group_with_id(group.id, group.name.clone())?;
        applied.groups_created.push(group.id);
    }

    // Then the entries. Each one is inserted, replaced or skipped, and every arrival is recorded
    // with the group it belongs in and whether the export marked it a favourite.
    let mut arrivals: Vec<Arrival> = Vec::new();
    for imported in &report.entries {
        let position = imported.position;
        let choice = choices.get(&position).copied().unwrap_or_else(|| {
            if same_content_of_vault(vault, imported) {
                Choice::Skip
            } else {
                Choice::Add
            }
        });

        match choice {
            Choice::Skip => applied.skipped += 1,
            Choice::Replace(id) => {
                // The identifier stays, so the entry keeps its group and its place: what the user
                // chose is which content is right, not which row it is.
                vault.replace(id, imported.entry.duplicate()?)?;
                applied.replaced.push(id);
            }
            Choice::Add | Choice::KeepBoth => {
                let id = vault.insert(imported.entry.duplicate()?)?;
                applied.added.push(id);
                arrivals.push(Arrival {
                    id,
                    group: target_group(vault, imported),
                    favorite: imported.favorite,
                    position,
                });
            }
        }
    }

    place(vault, &order_arrivals(&arrivals))?;

    Ok(applied)
}

/// One entry the import added, with what decides where it goes.
struct Arrival {
    /// The identifier it received.
    id: EntryId,
    /// The group it belongs in.
    group: GroupId,
    /// Whether the export marked it a favourite.
    favorite: bool,
    /// Where it was in the export, which is the order within one kind.
    position: usize,
}

/// The order each group receives its arrivals in.
///
/// Favourites come first, and each set keeps the order the export listed them - the export has no
/// other order to offer, and inventing one would put the user's own arrangement out of reach.
fn order_arrivals(arrivals: &[Arrival]) -> BTreeMap<GroupId, Vec<EntryId>> {
    let mut ordered: BTreeMap<GroupId, Vec<(bool, usize, EntryId)>> = BTreeMap::new();
    for arrival in arrivals {
        ordered.entry(arrival.group).or_default().push((
            !arrival.favorite,
            arrival.position,
            arrival.id,
        ));
    }

    ordered
        .into_iter()
        .map(|(group, mut entries)| {
            entries.sort_unstable();
            (group, entries.into_iter().map(|(_, _, id)| id).collect())
        })
        .collect()
}
/// Appends arrivals to the groups they were placed in.
///
/// Named groups are set **before** the top group, because setting a group is what takes an entry
/// out of the top one; doing it the other way round would leave the arrivals in both lists for a
/// moment, and the reconciliation that follows such a state puts an entry that is in no group back
/// into the top one.
fn place(vault: &mut Vault, placements: &BTreeMap<GroupId, Vec<EntryId>>) -> Result<()> {
    let mut named: Vec<(&GroupId, &Vec<EntryId>)> = placements.iter().collect();
    named.sort_by_key(|(group, _)| group.is_top());

    for (group, arrivals) in named {
        let mut ordering: Vec<EntryId> = vault
            .ordering(group)
            .unwrap_or_default()
            .iter()
            .filter(|id| vault.get(id).is_some() && !arrivals.contains(id))
            .copied()
            .collect();
        ordering.extend(arrivals.iter().copied());
        vault.set_ordering(group, ordering)?;
    }
    Ok(())
}

/// The group an imported entry belongs in: the first one it names that the vault holds.
///
/// The model gives an entry **one** group, while an export can name several; the first is the one
/// the export listed first. An entry that names nothing, or only groups the export did not define,
/// goes to the top group - which is what "belongs to no named group" means here.
fn target_group(vault: &Vault, imported: &ImportedEntry) -> GroupId {
    imported
        .groups
        .iter()
        .find(|group| vault.group(group).is_some())
        .copied()
        .unwrap_or(GroupId::TOP)
}

/// Whether the vault already holds this entry, in every field the user can see.
fn same_content_of_vault(vault: &Vault, imported: &ImportedEntry) -> bool {
    vault
        .iter()
        .any(|(_, entry)| same_content(entry, &imported.entry))
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::import::{ImportFormat, ImportedEntry};

    /// A report built by reading text, which is the cheapest way to get realistic entries.
    fn report_of(lines: &str) -> ImportReport {
        crate::import::import(lines.as_bytes(), ImportFormat::Text, 1_700_000_000, None)
            .expect("the lines are valid UTF-8")
    }

    /// One entry, built the same way a scanned code would be.
    fn entry(uri: &str, now: u64) -> Entry {
        let parsed = crate::uri::parse(uri).expect("the uri is valid");
        crate::vault::entry_from_parsed_uri(parsed, now).expect("the entry is valid")
    }

    /// A vault holding one entry, and the identifier it received.
    fn vault_with(uri: &str) -> (Vault, EntryId) {
        let mut vault = Vault::new();
        let id = vault
            .insert(entry(uri, 1_600_000_000))
            .expect("the vault is empty");
        (vault, id)
    }

    /// An imported entry, for the tests that need one on its own.
    fn imported(position: usize, uri: &str) -> ImportedEntry {
        let mut report = report_of(uri);
        let mut only = report.entries.remove(0);
        only.position = position;
        only
    }

    #[test]
    fn an_entry_the_vault_already_holds_is_identical() {
        let (vault, id) = vault_with("otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP");
        // The same entry, written with a different creation time: the timestamps say when a copy
        // was written, not which account it is.
        let report = report_of("otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP");

        let matches = compare(&report, &vault);
        assert_eq!(matches.len(), 1);
        assert!(matches[0].identical, "actual {matches:?}");
        assert_eq!(matches[0].existing, vec![id]);
        assert!(matches[0].differences.is_empty());
    }

    #[test]
    fn an_entry_with_the_same_secret_but_a_different_name_is_a_question() {
        let (vault, id) = vault_with("otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP");
        let report = report_of("otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&digits=8");

        let matches = compare(&report, &vault);
        assert!(!matches[0].identical);
        assert_eq!(
            matches[0].existing,
            vec![id],
            "the secret is what identifies it"
        );
        assert_eq!(
            matches[0].differences,
            vec![Difference::Digits],
            "the interface has to be able to say what would change"
        );
    }

    #[test]
    fn an_entry_nothing_matches_is_new() {
        let (vault, _) = vault_with("otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP");
        let report = report_of("otpauth://totp/Bank:bob?secret=KRSXG5CTMVRXEZLU");

        let matches = compare(&report, &vault);
        assert!(matches[0].is_new());
        assert!(!matches[0].identical);
        assert!(matches[0].differences.is_empty());
    }

    #[test]
    fn applying_without_answers_skips_what_is_there_and_adds_what_is_not() {
        let (mut vault, existing) =
            vault_with("otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP");
        let report = report_of(
            "otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP\n\
             otpauth://totp/Bank:bob?secret=KRSXG5CTMVRXEZLU\n",
        );

        let applied = apply(&mut vault, &report, &HashMap::new()).expect("applying cannot fail");
        assert_eq!(applied.skipped, 1);
        assert_eq!(applied.added.len(), 1);
        assert!(applied.replaced.is_empty());

        assert_eq!(vault.len(), 2);
        assert!(vault.get(&existing).is_some(), "the existing entry stays");
        let ordering: Vec<&Entry> = vault
            .ordering(&GroupId::TOP)
            .expect("the top group exists")
            .iter()
            .filter_map(|id| vault.get(id))
            .collect();
        assert_eq!(ordering.len(), 2);
        assert_eq!(ordering[1].account, "bob", "the arrival is appended");
    }

    #[test]
    fn a_group_the_export_names_is_created_and_receives_its_entries() {
        let mut vault = Vault::new();
        let mut report = report_of("otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP");
        let group = GroupId::from_bytes([0x5A; GroupId::LEN]);
        report.groups.push(crate::import::ImportedGroup {
            id: group,
            name: "Work".to_owned(),
        });
        report.entries[0].groups.push(group);

        let applied = apply(&mut vault, &report, &HashMap::new()).expect("applying cannot fail");
        assert_eq!(applied.groups_created, vec![group]);
        assert_eq!(
            vault.group(&group).map(|found| found.name.as_str()),
            Some("Work")
        );
        let placed: Vec<EntryId> = vault
            .ordering(&group)
            .expect("the group has an ordering")
            .to_vec();
        assert_eq!(placed, applied.added, "the entry is in the group it named");
        assert!(
            vault
                .ordering(&GroupId::TOP)
                .expect("the top group exists")
                .is_empty(),
            "and no longer in the top group"
        );

        // Applying the same report again creates nothing twice and adds nothing twice.
        let again = apply(&mut vault, &report, &HashMap::new()).expect("applying cannot fail");
        assert_eq!(again.groups_created.len(), 0);
        assert_eq!(again.groups_existing, vec![group]);
        assert_eq!(again.skipped, 1, "the entry is already there");
        assert_eq!(vault.len(), 1);
    }

    #[test]
    fn favourites_are_placed_before_the_rest() {
        let mut vault = Vault::new();
        let mut report = report_of(
            "otpauth://totp/First:a?secret=JBSWY3DPEHPK3PXP\n\
             otpauth://totp/Second:b?secret=KRSXG5CTMVRXEZLU\n\
             otpauth://totp/Third:c?secret=MFRGGZDFMZTWQ2LK\n",
        );
        // The last entry is the favourite, so it must end up first.
        report.entries[2].favorite = true;

        let applied = apply(&mut vault, &report, &HashMap::new()).expect("applying cannot fail");
        let ordering = vault.ordering(&GroupId::TOP).expect("the top group exists");
        assert_eq!(
            ordering,
            [applied.added[2], applied.added[0], applied.added[1]],
            "the favourite comes first, and the rest keep the export order"
        );
    }

    #[test]
    fn replacing_keeps_the_identifier_and_the_place() {
        let (mut vault, existing) =
            vault_with("otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP");
        let report = report_of("otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&digits=8");

        let mut choices = HashMap::new();
        choices.insert(1_usize, Choice::Replace(existing));
        let applied = apply(&mut vault, &report, &choices).expect("applying cannot fail");

        assert_eq!(applied.replaced, vec![existing]);
        assert!(applied.added.is_empty());
        assert_eq!(vault.len(), 1);
        assert_eq!(
            vault.get(&existing).map(|entry| entry.digits),
            Some(crate::otp::Digits::EIGHT),
            "the content came from the import"
        );
        assert_eq!(
            vault.ordering(&GroupId::TOP),
            Some(vec![existing]),
            "and the row did not move"
        );
    }

    #[test]
    fn keeping_both_adds_a_second_entry_with_the_same_secret() {
        let (mut vault, existing) =
            vault_with("otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP");
        let report = report_of("otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&digits=8");

        let mut choices = HashMap::new();
        choices.insert(1_usize, Choice::KeepBoth);
        let applied = apply(&mut vault, &report, &choices).expect("applying cannot fail");

        assert_eq!(applied.added.len(), 1);
        assert_eq!(vault.len(), 2);
        assert!(vault.get(&existing).is_some());
    }

    #[test]
    fn an_answer_for_an_entry_the_vault_no_longer_holds_is_refused() {
        let mut vault = Vault::new();
        let report = report_of("otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP");
        let missing = EntryId::from_bytes([0x11; EntryId::LEN]);

        let mut choices = HashMap::new();
        choices.insert(1_usize, Choice::Replace(missing));
        let result = apply(&mut vault, &report, &choices);
        assert!(
            matches!(result, Err(crate::Error::VaultEntryNotFound)),
            "actual {result:?}"
        );
        assert_eq!(vault.len(), 0, "a refused answer writes nothing");
    }

    #[test]
    fn the_comparison_reports_every_field_that_differs() {
        let existing = entry("otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP", 0);
        let other = entry(
            "otpauth://hotp/Other:bob?secret=JBSWY3DPEHPK3PXP&digits=8&counter=9",
            0,
        );
        let mut found = differences(&existing, &other);
        found.sort_by_key(|difference| format!("{difference:?}"));
        assert!(found.contains(&Difference::Name));
        assert!(found.contains(&Difference::Issuer));
        assert!(found.contains(&Difference::Account));
        assert!(found.contains(&Difference::Digits));
        assert!(found.contains(&Difference::Kind));
        assert!(!found.contains(&Difference::Note), "both notes are empty");
    }

    #[test]
    fn a_position_from_the_export_is_what_an_answer_is_keyed_by() {
        let (vault, _) = vault_with("otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP");
        let mut report = report_of("otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP");
        // A report whose entry carries a position from the middle of a file: the answer is keyed by
        // that number, not by the index inside the report.
        report.entries[0].position = 7;
        let only = imported(7, "otpauth://totp/Other:bob?secret=KRSXG5CTMVRXEZLU");
        assert_eq!(only.position, 7);

        let matches = compare(&report, &vault);
        assert_eq!(matches[0].position, 7);
    }
}
