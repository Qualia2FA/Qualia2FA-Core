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

//! Groups: the tree that arranges entries, and the ordered lists it is built from.
//!
//! A group is an account-level fact: a named collection of entries and of **child groups**. This
//! module holds the two types that carry it, [`GroupId`] and [`Group`], plus [`GroupChild`]; the
//! vault stores them and the file format writes them.
//!
//! # The tree is the lists, not a parent field
//!
//! A group record is **its ordered list of child references**. Which group is the parent of a
//! reference is decided by "whose list it appears in", never by a field on the child. There is no
//! second copy of that fact to disagree with the first:
//!
//! - moving one child rewrites two lists, and each list is written whole;
//! - an entry's membership is derived from the lists, so the entry format needs neither "which
//!   group am I in" nor "which position do I hold";
//! - the file format, the sync payload and the in-memory model all hold exactly one shape.
//!
//! The cost is that a list is a **sequence, not a set**: two devices that hold the same children
//! in different orders hold different lists, and that difference is a conflict to show the user
//! rather than something to merge automatically.
//!
//! # The top group
//!
//! Entries that belong to no named group still form one sortable whole, and it is a group like any
//! other with the reserved identifier [`GroupId::TOP`]. The user interface pins it at the top and
//! offers no way to delete it, so [`Vault::remove_group`](crate::vault::Vault::remove_group) refuses
//! it. It is the root of the tree: named groups that have no parent live in its child list.
//!
//! # Depth
//!
//! The top group is depth zero. Named groups may be nested up to
//! [`Vault::MAX_GROUP_DEPTH`](crate::vault::Vault::MAX_GROUP_DEPTH); entries may sit at any
//! depth. The vault enforces both when a list is written, and the parser repairs a file that
//! violates them.

use crate::{Error, Result};

/// Identifier of a group: a 128-bit value, the same shape as an entry identifier.
///
/// It sits in the vault file in plaintext, exactly like an entry identifier, because the record
/// header has one 16-byte identifier field and the record kind decides what it means. It
/// carries no semantics and reveals nothing: its only purpose is to let two devices and the user
/// interface name the same group.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GroupId([u8; Self::LEN]);

impl GroupId {
    /// Byte length of an identifier.
    pub const LEN: usize = 16;

    /// The reserved identifier of the **top group**: the root of the tree.
    ///
    /// All zeroes, which no generated identifier can be in practice: [`GroupId::generate`]
    /// draws 128 random bits, so the chance of a collision is the chance of drawing exactly
    /// this value. The reserved value is what makes the top group a group like any other -
    /// storable, orderable and syncable - instead of a special case in every match.
    pub const TOP: Self = Self([0; Self::LEN]);

    /// Generates a new random identifier.
    ///
    /// # Errors
    ///
    /// Returns [`Error::RandomnessUnavailable`] when the OS random source is unavailable. There
    /// is **no** fallback to a userspace PRNG.
    pub fn generate() -> Result<Self> {
        let mut bytes = [0_u8; Self::LEN];
        crate::getrandom::fill(&mut bytes).map_err(|_| Error::RandomnessUnavailable)?;
        Ok(Self(bytes))
    }

    /// Builds an identifier from a byte array, as read from a file.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }

    /// Returns the raw bytes, used to write the file and to build the AAD.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }

    /// Whether this is the reserved top group.
    #[must_use]
    pub const fn is_top(&self) -> bool {
        let mut index = 0;
        while index < Self::LEN {
            if self.0[index] != 0 {
                return false;
            }
            index += 1;
        }
        true
    }
}

impl core::fmt::Debug for GroupId {
    /// Prints the hexadecimal form, with the top group called out by name.
    ///
    /// The identifier is not a secret (it sits in the file in plaintext); the name matters
    /// because "the top group" is what a reader of a log or a failing test is looking for.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.is_top() {
            return f.write_str("GroupId(TOP)");
        }
        write!(f, "GroupId(")?;
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        f.write_str(")")
    }
}

/// One child of a group: either an entry or another group.
///
/// The two live in one list because the list **is** the display order: an entry and a child group
/// have to be comparable to say "this entry comes before that group". The variant is the child's
/// kind, so the file format needs one node and the merge one comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum GroupChild {
    /// An entry that belongs to no other group.
    Entry(crate::vault::EntryId),
    /// A named group whose children hang here.
    Group(GroupId),
}

impl GroupChild {
    /// The 16-byte identifier of the child, whichever kind it is.
    #[must_use]
    pub const fn id_bytes(&self) -> &[u8; GroupId::LEN] {
        match self {
            Self::Entry(id) => id.as_bytes(),
            Self::Group(id) => id.as_bytes(),
        }
    }
}

/// A named group: a name and the ordered list of its children.
///
/// The list **is** the order: the child at index `i` comes after the child at index `i - 1` and
/// before the one at index `i + 1`.
///
/// # Why this one does implement `Clone`
///
/// A group holds a name and identifiers - **no secret material**, and no key material of any
/// kind. Copying it is free in the sense that matters here, and both a conflict (which must show
/// the two arrangements side by side) and the merge that reports it need copies. Compare
/// [`crate::vault::Entry`], which deliberately has no `Clone`: copying an entry means copying a
/// seed, so that path goes through an explicit [`crate::vault::Entry::duplicate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    /// User-visible name. Empty for the top group, which is not nameable.
    pub name: String,
    /// The entries and child groups of this group, in display order.
    ///
    /// Every reference may appear in **at most one** list of one group; the vault keeps that
    /// true (see [`Vault::set_children`](crate::vault::Vault::set_children)), and the parser
    /// repairs a file that violates it.
    pub children: Vec<GroupChild>,
}

impl Group {
    /// Maximum number of children one group can hold.
    ///
    /// The list travels in a single length-prefixed node, so it is bounded by
    /// [`crate::vault::Entry::MAX_FIELD_LEN`]: `(65_536 - 5) / (1 + 16)`, the five bytes being
    /// the node tag and its u32 length and the seventeen the size of one child reference. The
    /// limit is far above any real group - a thousand entries already fills a screen many times
    /// over.
    pub const MAX_CHILDREN: usize = (crate::vault::Entry::MAX_FIELD_LEN - 5) / (1 + GroupId::LEN);

    /// Builds a group from its parts.
    ///
    /// # Errors
    ///
    /// Returns [`Error::FieldTooLong`] when the name exceeds
    /// [`Entry::MAX_FIELD_LEN`](crate::vault::Entry::MAX_FIELD_LEN), and
    /// [`Error::VaultGroupTooManyChildren`] when the list holds more than [`Group::MAX_CHILDREN`]
    /// references.
    ///
    /// A reference that appears twice **within** the list is rejected as
    /// [`Error::VaultGroupDuplicateChild`]: the list is an ordering, and one child cannot occupy
    /// two positions in the same ordering. Whether a child may appear in two *different* groups
    /// is a question for the vault, not for one group.
    pub fn new(name: String, children: Vec<GroupChild>) -> Result<Self> {
        if name.len() > crate::vault::Entry::MAX_FIELD_LEN {
            return Err(Error::FieldTooLong {
                field: "group name",
                limit: crate::vault::Entry::MAX_FIELD_LEN,
                actual: name.len(),
            });
        }
        if children.len() > Self::MAX_CHILDREN {
            return Err(Error::VaultGroupTooManyChildren {
                limit: Self::MAX_CHILDREN,
                actual: children.len(),
            });
        }
        if first_duplicate(&children).is_some() {
            return Err(Error::VaultGroupDuplicateChild);
        }
        Ok(Self { name, children })
    }

    /// The top group, holding the given children in the given order.
    ///
    /// # Errors
    ///
    /// As [`Group::new`]; the name is empty by definition.
    pub fn top(children: Vec<GroupChild>) -> Result<Self> {
        Self::new(String::new(), children)
    }

    /// An empty top group.
    ///
    /// Used when a vault gains its first entry or group, or when a file that has entries but no
    /// group records is read: the top group then holds every entry, in file order.
    pub(crate) fn top_empty() -> Self {
        Self {
            name: String::new(),
            children: Vec::new(),
        }
    }

    /// Whether this group is the reserved top group, by name.
    ///
    /// Only the root has no name; a named group may be given an empty one by a file written by
    /// another implementation, and that is still a named group. Prefer
    /// [`GroupId::is_top`] where the identifier is at hand.
    #[must_use]
    pub fn has_no_name(&self) -> bool {
        self.name.is_empty()
    }

    /// The entry identifiers in this group, in display order.
    ///
    /// A **view**: the child list is the truth, and this is the subset that names entries. A
    /// caller that needs the whole arrangement reads [`Group::children`].
    #[must_use]
    pub fn entry_ids(&self) -> Vec<crate::vault::EntryId> {
        self.children
            .iter()
            .filter_map(|child| match child {
                GroupChild::Entry(id) => Some(*id),
                GroupChild::Group(_) => None,
            })
            .collect()
    }
}

/// Returns the first reference that appears more than once, if any.
///
/// Quadratic in the list length and deliberately so: the lists are small (a screenful or two),
/// the check runs once per construction rather than per comparison, and the alternative - a
/// sorted copy - would mean copying the list on a path that runs for every group of every parse.
fn first_duplicate(children: &[GroupChild]) -> Option<GroupChild> {
    for (index, child) in children.iter().enumerate() {
        if children[index + 1..].contains(child) {
            return Some(*child);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::EntryId;

    fn id(seed: u8) -> EntryId {
        EntryId::from_bytes([seed; EntryId::LEN])
    }

    fn gid(seed: u8) -> GroupId {
        GroupId::from_bytes([seed; GroupId::LEN])
    }

    fn child(seed: u8) -> GroupChild {
        GroupChild::Entry(id(seed))
    }

    #[test]
    fn the_top_identifier_is_reserved_and_recognized() {
        assert!(GroupId::TOP.is_top());
        assert_eq!(GroupId::TOP.as_bytes(), &[0_u8; GroupId::LEN]);
        assert_eq!(format!("{:?}", GroupId::TOP), "GroupId(TOP)");
    }

    #[test]
    fn a_generated_identifier_is_never_the_reserved_one() {
        for _ in 0..64 {
            let generated = GroupId::generate().expect("OS randomness available");
            assert!(
                !generated.is_top(),
                "a generated identifier collided with the reserved value"
            );
            assert_eq!(
                format!("{generated:?}").len(),
                "GroupId()".len() + 2 * GroupId::LEN
            );
        }
    }

    #[test]
    fn a_group_keeps_its_name_and_children() {
        let group = Group::new("Work".to_owned(), vec![child(1), GroupChild::Group(gid(2))])
            .expect("valid group");
        assert_eq!(group.name, "Work");
        assert_eq!(group.children, vec![child(1), GroupChild::Group(gid(2))]);
        assert_eq!(group.entry_ids(), vec![id(1)]);
        assert!(!group.has_no_name());
        assert!(Group::top(vec![]).expect("valid group").has_no_name());
    }

    #[test]
    fn a_duplicate_child_in_one_list_is_rejected() {
        let err = Group::new("Work".to_owned(), vec![child(1), child(2), child(1)]);
        assert!(
            matches!(err, Err(Error::VaultGroupDuplicateChild)),
            "one child cannot hold two positions in the same ordering"
        );

        assert!(
            Group::new("Work".to_owned(), vec![child(1), child(2), child(3)]).is_ok(),
            "distinct references are fine"
        );
    }

    #[test]
    fn an_over_long_name_or_list_is_rejected() {
        let long = "n".repeat(crate::vault::Entry::MAX_FIELD_LEN + 1);
        assert!(matches!(
            Group::new(long, vec![]),
            Err(Error::FieldTooLong { .. })
        ));

        let too_many: Vec<GroupChild> = (0..=Group::MAX_CHILDREN)
            .map(|index| {
                let mut bytes = [0_u8; EntryId::LEN];
                bytes[..8].copy_from_slice(
                    &u64::try_from(index)
                        .expect("the test range fits in u64")
                        .to_be_bytes(),
                );
                GroupChild::Entry(EntryId::from_bytes(bytes))
            })
            .collect();
        assert!(
            matches!(
                Group::new(String::new(), too_many),
                Err(Error::VaultGroupTooManyChildren { .. })
            ),
            "the list travels in one node, so it is bounded by MAX_FIELD_LEN"
        );
    }

    /// The bound is the one the node can hold: 17 bytes per reference plus the node header.
    #[test]
    fn the_child_limit_matches_the_node_it_travels_in() {
        assert_eq!(Group::MAX_CHILDREN, 3854);
        let per_child = 1 + GroupId::LEN;
        assert!(5 + Group::MAX_CHILDREN * per_child <= crate::vault::Entry::MAX_FIELD_LEN);
        assert!(5 + (Group::MAX_CHILDREN + 1) * per_child > crate::vault::Entry::MAX_FIELD_LEN);
    }
}
