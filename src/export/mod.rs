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

//! Writing the vault out in a form that can be read again somewhere else.
//!
//! # Two kinds of export, and they are not interchangeable
//!
//! - **A portable vault** ([`ExportFormat::Vault`], [`ExportFormat::EncryptedVault`]) is this
//!   application's own backup: the master key and the whole encrypted vault, in one `.q2fa`
//!   file. It restores everything - entries, the group **tree**, the icons - on a clean device.
//! - **An export for another authenticator** ([`ExportFormat::Text`], [`ExportFormat::Json`],
//!   [`ExportFormat::EncryptedJson`], [`ExportFormat::Html`]) is written in the shapes the
//!   reference implementation reads. What each of them can carry is stated by
//!   [`ExportFormat::group_carrying`]: the text and HTML forms have no group at all, and even
//!   the JSON forms carry only one flat level of group names, not the nesting.
//!
//! # The formats are the reference implementation's, not this library's
//!
//! An export exists to be read by something else, so its spelling is decided by the reader
//! rather than by what would be convenient here: the JSON object, the table of the HTML
//! export, the one-URI-per-line text file and the `motp:` form of an mOTP URI are all the
//! shapes the reference implementation writes and reads. Nothing is added, and nothing is
//! renamed. In particular the icon fields of the JSON export are `icon` (base64), `icon_mime`
//! and `icon_hash`, exactly as the reference format spells them.
//!
//! # An export round trips through this library's own reader
//!
//! Every external format here has a reader in [`crate::import`], and each writer's tests walk the
//! whole way: vault → file → reader → entry by entry comparison. That is the property that
//! matters, because the two halves were written against the same document and a shared
//! misunderstanding would otherwise stay invisible.
//!
//! What the round trip cannot preserve is what a format does not carry: the text and HTML
//! exports have no field for the groups or for the ordering, neither has one for the account
//! name (a URI carries it in the label), and the JSON forms lose the nesting. Each writer's
//! documentation says which fields survive and which do not.
//!
//! # Nothing about an entry appears in an error
//!
//! The same rule as the reader's: an error is a position and a reason. An export that cannot
//! be written says which entry it stopped at, never what the entry held.
//!
//! # The vault is not modified
//!
//! Every entry point takes a `&Vault` or a `&VaultFile` and returns the file's bytes; the caller
//! writes them wherever it likes. This library has no I/O (see the crate documentation), and an
//! export is not an exception.
//!
//! # The plain `.q2fa` container holds the master key in clear
//!
//! That is what lets it restore an account without the old device or a passphrase. It also means
//! the file is as sensitive as every secret in the vault, and the interface must say so. This
//! library cannot make the format safer than it is; it only refuses to write it silently under
//! another name.

pub mod html;
pub mod json;
pub(crate) mod png;
pub mod text;

use std::collections::HashSet;

use crate::vault::{Entry, EntryId, Group, GroupId, Vault, VaultFile};
use crate::{Error, Result};

/// An export format this library writes.
///
/// The six are the interface's numbered choices, in the order the interface offers them: the two
/// `.q2fa` containers first, then the four shapes another authenticator reads. Which one a
/// caller offers is a user interface question; the differences that matter to the library are
/// [`ExportFormat::needs_password`] and [`ExportFormat::group_carrying`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    /// A plain `.q2fa`: the master key in clear plus the whole vault ciphertext.
    ///
    /// This is the format that restores an account on a clean device. Whoever holds the file
    /// holds the master key, which is why the interface warns about it more strongly than about
    /// the encrypted form.
    Vault,
    /// A passphrase-protected `.q2fa`: the master key wrapped by [`crate::recovery`] plus the
    /// whole vault ciphertext.
    EncryptedVault,
    /// The text export: one `otpauth://` URI per line.
    Text,
    /// The JSON export, readable as it stands.
    Json,
    /// The JSON export, encrypted with a password the caller supplies.
    EncryptedJson,
    /// The HTML export: a table with one row per entry and the code drawn beside it.
    Html,
}

/// How much of the group tree a format can carry.
///
/// A boolean is too coarse: the Aegis JSON carries the group **names and memberships** but not
/// the nesting, so a caller that offered it as "keeps your groups" would be saying something
/// false. The interface labels each format from this answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupCarrying {
    /// The format has nowhere to put a group.
    None,
    /// The format carries the named groups and which entry belongs to which, as one flat level.
    FlatGroups,
    /// The format carries the whole tree: parents, nesting and the mixed order of children.
    FullTree,
}

impl GroupCarrying {
    /// Whether the format carries anything about groups.
    #[must_use]
    pub const fn carries_anything(self) -> bool {
        !matches!(self, Self::None)
    }

    /// Whether the format keeps the nesting.
    #[must_use]
    pub const fn carries_nesting(self) -> bool {
        matches!(self, Self::FullTree)
    }
}

impl ExportFormat {
    /// Every format, in the order the interface offers them.
    pub const ALL: [Self; 6] = [
        Self::Vault,
        Self::EncryptedVault,
        Self::Text,
        Self::Json,
        Self::EncryptedJson,
        Self::Html,
    ];

    /// The name used in messages and diagnostics.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Vault => "vault",
            Self::EncryptedVault => "encrypted vault",
            Self::Text => "text",
            Self::Json => "JSON",
            Self::EncryptedJson => "encrypted JSON",
            Self::Html => "HTML",
        }
    }

    /// The file name extension this format is normally written with.
    ///
    /// Both JSON forms share one: they are the same file with and without a password, and a
    /// reader tells them apart by the `db` field being a string rather than an object. Both
    /// `.q2fa` forms share one for the same reason: they are told apart by their magic.
    #[must_use]
    pub const fn extension(self) -> &'static str {
        match self {
            Self::Vault | Self::EncryptedVault => "q2fa",
            Self::Text => "txt",
            Self::Json | Self::EncryptedJson => "json",
            Self::Html => "html",
        }
    }

    /// Whether this format is written with a password.
    ///
    /// A caller uses it to decide whether to ask for one **before** calling [`export`], rather
    /// than calling and handling [`Error::ExportPasswordRequired`].
    #[must_use]
    pub const fn needs_password(self) -> bool {
        matches!(self, Self::EncryptedVault | Self::EncryptedJson)
    }

    /// How much of the group tree this format carries.
    #[must_use]
    pub const fn group_carrying(self) -> GroupCarrying {
        match self {
            Self::Vault | Self::EncryptedVault => GroupCarrying::FullTree,
            Self::Json | Self::EncryptedJson => GroupCarrying::FlatGroups,
            Self::Text | Self::Html => GroupCarrying::None,
        }
    }

    /// Whether this format carries the groups at all.
    #[must_use]
    pub const fn carries_groups(self) -> bool {
        self.group_carrying().carries_anything()
    }
}

/// Writes the vault out in one of the formats.
///
/// `password` is the UTF-8 bytes of the password, and is looked at only by
/// [`ExportFormat::EncryptedVault`] and [`ExportFormat::EncryptedJson`]: the derivations consume
/// bytes, and hashing text would mean choosing a normalization the format does not specify. A
/// password supplied for any other format is ignored rather than refused, since the caller has
/// already chosen the format and there is nothing it could open.
///
/// # It takes the whole vault file, not only its contents
///
/// The two `.q2fa` containers carry the **master key** beside the ciphertext, so the export
/// cannot be written from the decrypted contents alone. Passing the [`VaultFile`] keeps the key
/// and the contents together, which is also what stops "this file was written with another
/// key".
///
/// # Errors
///
/// - [`Error::ExportPasswordRequired`]: an encrypted export was asked for with no password.
/// - [`Error::ExportPasswordEmpty`]: the password is empty, which would leave the file open to
///   anyone who tries nothing at all.
/// - [`Error::UriAccountContainsColon`]: one entry's account name cannot be written into a URI
///   label (see [`crate::uri::serialize`]). Reported rather than worked around: the file would
///   read back as a different entry.
/// - [`Error::ExportQrTooLong`]: one entry's URI does not fit a QR code, so the HTML export
///   cannot draw it.
/// - [`Error::FieldTooLong`]: an entry holds a field the file format cannot represent.
///   Reachable only for an entry built by hand; the vault's own parser would have refused it.
/// - [`Error::ExportTooLarge`]: the vault does not fit a portable container.
/// - [`Error::RandomnessUnavailable`]: a salt or a nonce could not be drawn.
pub fn export(file: &VaultFile, format: ExportFormat, password: Option<&[u8]>) -> Result<Vec<u8>> {
    let vault = file.vault();
    let bytes = match format {
        ExportFormat::Vault => {
            // No password: this format is defined as the file that restores without one.
            portable_bytes(file)?
        }
        ExportFormat::EncryptedVault => {
            let password = password.ok_or(Error::ExportPasswordRequired)?;
            if password.is_empty() {
                return Err(Error::ExportPasswordEmpty);
            }
            let passphrase =
                core::str::from_utf8(password).map_err(|_| Error::ExportParameterRefused {
                    parameter: "the passphrase is not UTF-8",
                })?;
            let recovery = crate::recovery::export(
                file.master_key(),
                &crate::SecretString::from(passphrase.to_owned()),
                &crate::recovery::KdfParams::recommended(),
            )?;
            let data = file.serialize()?;
            crate::portable::pack_encrypted(&recovery, &data)?
        }
        ExportFormat::Text => text::write(vault)?.into_bytes(),
        ExportFormat::Json => json::write(vault)?.into_bytes(),
        ExportFormat::Html => html::write(vault)?.into_bytes(),
        ExportFormat::EncryptedJson => {
            let password = password.ok_or(Error::ExportPasswordRequired)?;
            if password.is_empty() {
                return Err(Error::ExportPasswordEmpty);
            }
            json::write_encrypted(vault, password)?.into_bytes()
        }
    };
    Ok(bytes)
}

/// Packs the plain `.q2fa` container: the master key in clear plus the vault ciphertext.
///
/// # Errors
///
/// As [`VaultFile::serialize`] and [`crate::portable::pack_plain`].
fn portable_bytes(file: &VaultFile) -> Result<Vec<u8>> {
    let data = file.serialize()?;
    crate::portable::pack_plain(file.master_key(), &data)
}

/// One entry, with what the writers need beside it.
pub(crate) struct Item<'a> {
    /// The entry's identifier, which the JSON export writes as its UUID.
    pub(crate) id: EntryId,
    /// The entry itself.
    pub(crate) entry: &'a Entry,
    /// The named group it belongs to, or `None` for the top group.
    pub(crate) group: Option<GroupId>,
    /// Where it sits in the export, counting from 1. Used in errors, never its name.
    pub(crate) position: usize,
}

/// Walks the vault in the order an export writes it.
///
/// The order is the one the user sees: the tree in pre-order, and inside each group the
/// arrangement the vault holds - entries and child groups mixed. That is the same walk the
/// interface performs, which is what makes an exported file look like the application.
///
/// Each item's `group` is the **immediate** parent: the Aegis format has one flat level, so an
/// entry inside a nested group is written as belonging to that group by name. The nesting is
/// lost there by definition, which is what [`GroupCarrying::FlatGroups`] says.
///
/// # An entry no ordering mentions
///
/// Every path through this library puts an entry into a group (see
/// [`crate::vault::Vault::insert`]), so this cannot normally happen. It is handled anyway,
/// because the alternative is an export that silently leaves entries out: whatever is left
/// after the walk is appended at the end, with no group.
pub(crate) fn items(vault: &Vault) -> Vec<Item<'_>> {
    let mut out: Vec<Item<'_>> = Vec::with_capacity(vault.len());
    let mut seen: HashSet<EntryId> = HashSet::with_capacity(vault.len());

    for (group_id, _) in vault.groups() {
        let named = (!group_id.is_top()).then_some(*group_id);
        for (id, entry) in vault.entries_in(group_id) {
            if !seen.insert(*id) {
                continue;
            }
            out.push(Item {
                id: *id,
                entry,
                group: named,
                position: out.len() + 1,
            });
        }
    }

    for (id, entry) in vault.iter() {
        if !seen.insert(*id) {
            continue;
        }
        out.push(Item {
            id: *id,
            entry,
            group: None,
            position: out.len() + 1,
        });
    }

    out
}

/// The named groups, in the order the vault displays them.
///
/// The top group is left out: it is not a group a file can name, it is "everything that is in
/// no named group", and the reference implementation's format has no record for it.
///
/// The list is **flat**: a nested group appears beside its parent, and an entry names the group
/// it is directly in. That is the most the reference format can carry, which is why
/// [`ExportFormat::Json`] reports [`GroupCarrying::FlatGroups`] and not
/// [`GroupCarrying::FullTree`].
pub(crate) fn named_groups(vault: &Vault) -> Vec<(GroupId, &Group)> {
    vault
        .groups()
        .filter(|(id, _)| !id.is_top())
        .map(|(id, group)| (*id, group))
        .collect()
}

/// The URI of one entry, in the spelling the reference implementation writes.
///
/// # The label is the account, and the name is the fallback
///
/// A URI has one label and the reference format has no second field, so an entry with both a
/// name and an account can carry only one of them. The account wins because it is what the
/// label means (it is where the account came from when the URI was read), and the name is used
/// when there is none - an entry created in this application has a name from the start and
/// often no account at all.
///
/// # Errors
///
/// [`crate::uri::serialize`]'s: an account name containing `:` cannot be told apart from the
/// issuer separator once the label is decoded, so the URI is refused rather than written into
/// something that reads back differently.
pub(crate) fn uri_of(entry: &Entry) -> Result<String> {
    // The copy is explicit because `OtpSecret` is deliberately neither `Clone` nor copyable by
    // accident: `Entry::duplicate` is the one sanctioned way to get a second, owned entry.
    let Entry {
        name,
        issuer,
        account,
        secret,
        algorithm,
        digits,
        kind,
        ..
    } = entry.duplicate()?;

    let label = if account.is_empty() { name } else { account };
    crate::uri::serialize(&crate::uri::OtpAuth {
        kind,
        secret,
        issuer,
        account: label,
        algorithm,
        digits,
    })
}

/// The name the formats use for a scheme.
pub(crate) const fn type_name(kind: &crate::vault::EntryKind) -> &'static str {
    use crate::vault::EntryKind;
    match kind {
        EntryKind::Totp { .. } => "totp",
        EntryKind::Hotp { .. } => "hotp",
        EntryKind::Steam => "steam",
        EntryKind::Motp { .. } => "motp",
        EntryKind::Yandex { .. } => "yandex",
    }
}

/// The hash algorithm to write for an entry.
///
/// # The scheme wins over the entry's own field
///
/// Three of the five schemes fix their own algorithm: mOTP is MD5-based, Yandex OTP is SHA-256,
/// Steam Guard is SHA-1. The entry model keeps a field there anyway (it is one type for every
/// entry), and what decides the code a user sees is the scheme - so that is what is written.
/// Writing the field instead would produce a file whose declared algorithm contradicts the
/// scheme whenever an entry was built by hand, and a reader that believes the declaration would
/// compute codes that never match.
pub(crate) const fn algorithm_name(
    kind: &crate::vault::EntryKind,
    algorithm: crate::otp::Algorithm,
) -> &'static str {
    use crate::otp::Algorithm;
    use crate::vault::EntryKind;
    match kind {
        EntryKind::Motp { .. } => "MD5",
        EntryKind::Yandex { .. } => "SHA256",
        EntryKind::Steam => "SHA1",
        EntryKind::Totp { .. } | EntryKind::Hotp { .. } => match algorithm {
            Algorithm::Sha1 => "SHA1",
            Algorithm::Sha256 => "SHA256",
            Algorithm::Sha512 => "SHA512",
        },
    }
}

/// Writes a 128-bit identifier as canonical UUID text.
///
/// The reference implementation's entries and groups are identified by UUIDs, so that is the
/// spelling its files carry. Dashes are written in the canonical places; a reader that strips
/// them (this library's own does) reads the same value either way.
pub(crate) fn uuid_text(bytes: &[u8; 16]) -> String {
    let mut out = String::with_capacity(36);
    for (index, byte) in bytes.iter().enumerate() {
        if matches!(index, 4 | 6 | 8 | 10) {
            out.push('-');
        }
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Writes bytes as lower-case hexadecimal.
pub(crate) fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Writes bytes as standard base64 (RFC 4648 §4): `+`, `/`, and `=` padding.
///
/// The alphabet is the standard one, not the URL-safe one, because that is what the format
/// writes for both the encrypted database and the image of its HTML export.
pub(crate) fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let mut block = [0_u8; 3];
        block[..chunk.len()].copy_from_slice(chunk);
        let bits = (u32::from(block[0]) << 16) | (u32::from(block[1]) << 8) | u32::from(block[2]);
        let letters = [
            ALPHABET[((bits >> 18) & 0x3F) as usize],
            ALPHABET[((bits >> 12) & 0x3F) as usize],
            ALPHABET[((bits >> 6) & 0x3F) as usize],
            ALPHABET[(bits & 0x3F) as usize],
        ];
        let keep = chunk.len() + 1;
        for (index, letter) in letters.iter().enumerate() {
            out.push(if index < keep {
                char::from(*letter)
            } else {
                '='
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_identifier_is_written_as_a_canonical_uuid() {
        let mut bytes = [0_u8; 16];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::try_from(index).expect("the index is small");
        }
        let text = uuid_text(&bytes);
        assert_eq!(text, "00010203-0405-0607-0809-0a0b0c0d0e0f");
        assert_eq!(text.len(), 36);
    }

    #[test]
    fn base64_is_the_standard_alphabet_with_padding() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"A"), "QQ==");
        assert_eq!(base64(b"AB"), "QUI=");
        assert_eq!(base64(b"ABC"), "QUJD");
        assert_eq!(base64(&[0xFB, 0xFF]), "+/8=");
    }

    #[test]
    fn hexadecimal_is_lower_case_and_two_digits_per_byte() {
        assert_eq!(hex(&[0x00, 0x0F, 0xFF]), "000fff");
        assert_eq!(hex(&[]), "");
    }

    /// What each format is called, what it is written with, and what it needs.
    ///
    /// A caller builds a file name and asks for a password from these answers, so they are part
    /// of the interface rather than an internal detail.
    #[test]
    fn the_formats_describe_themselves() {
        let formats = ExportFormat::ALL;
        let names: Vec<&str> = formats.iter().map(|format| format.name()).collect();
        assert_eq!(
            names,
            vec![
                "vault",
                "encrypted vault",
                "text",
                "JSON",
                "encrypted JSON",
                "HTML"
            ],
            "the order is the interface's fixed order"
        );

        let extensions: Vec<&str> = formats.iter().map(|format| format.extension()).collect();
        assert_eq!(
            extensions,
            vec!["q2fa", "q2fa", "txt", "json", "json", "html"]
        );
        let encrypted: Vec<bool> = formats
            .iter()
            .map(|format| format.needs_password())
            .collect();
        assert_eq!(
            encrypted,
            vec![false, true, false, false, true, false],
            "exactly the two encrypted forms ask for a password"
        );

        assert_eq!(
            ExportFormat::Vault.group_carrying(),
            GroupCarrying::FullTree
        );
        assert_eq!(
            ExportFormat::EncryptedVault.group_carrying(),
            GroupCarrying::FullTree
        );
        assert_eq!(
            ExportFormat::Json.group_carrying(),
            GroupCarrying::FlatGroups
        );
        assert_eq!(
            ExportFormat::EncryptedJson.group_carrying(),
            GroupCarrying::FlatGroups,
            "the JSON forms keep the group names and memberships, not the nesting"
        );
        assert!(!ExportFormat::Json.group_carrying().carries_nesting());
        assert_eq!(ExportFormat::Text.group_carrying(), GroupCarrying::None);
        assert_eq!(
            ExportFormat::Html.group_carrying(),
            GroupCarrying::None,
            "a list of URIs and a table have nowhere to put a group"
        );
    }

    /// An empty vault exports in every format without an error.
    ///
    /// A vault with no entries has nothing to write into a list of URIs, so the text export is
    /// an empty file - that is a legitimate export, not a failure. The others always have a
    /// container to write.
    #[test]
    fn every_format_writes_an_empty_vault() {
        let file = VaultFile::create().expect("OS randomness available");
        for format in ExportFormat::ALL {
            let password = format.needs_password().then_some(&b"password"[..]);
            let written = export(&file, format, password)
                .unwrap_or_else(|error| panic!("{} must write: {error}", format.name()));
            if format == ExportFormat::Text {
                assert!(written.is_empty(), "there are no entries to write");
            } else {
                assert!(
                    !written.is_empty(),
                    "{} must still produce a container",
                    format.name()
                );
            }
        }
    }

    /// The two `.q2fa` containers carry the master key and the vault, and can be unpacked again.
    #[test]
    fn the_portable_formats_carry_the_key_and_the_vault() {
        let mut file = VaultFile::create().expect("OS randomness available");
        file.vault_mut()
            .insert(
                crate::vault::Entry::new(
                    "GitHub".into(),
                    Some("GitHub".into()),
                    "alice".into(),
                    crate::otp::OtpSecret::from_base32("JBSWY3DPEHPK3PXP").expect("valid secret"),
                    crate::otp::Algorithm::Sha1,
                    crate::otp::Digits::SIX,
                    crate::vault::EntryKind::Totp { period: 30 },
                    String::new(),
                    1_700_000_000,
                    1_700_000_000,
                )
                .expect("valid entry"),
            )
            .expect("insertion succeeds");

        let plain =
            export(&file, ExportFormat::Vault, None).expect("the plain form needs no password");
        assert_eq!(&plain[..8], crate::portable::PLAIN_MAGIC);
        let parsed = crate::portable::parse(&plain).expect("it parses");
        assert_eq!(parsed.kind(), crate::portable::PortableKind::PlainVault);
        let vault_bytes = parsed.vault().expect("it carries the vault");
        let reopened = VaultFile::parse(
            crate::vault::MasterKey::from_bytes(crate::vault::master_key_to_bytes(
                file.master_key(),
            ))
            .expect("the length is correct"),
            vault_bytes,
        )
        .expect("the vault opens with the key the container carried");
        assert_eq!(reopened.vault().len(), 1);

        let encrypted = export(&file, ExportFormat::EncryptedVault, Some(b"password"))
            .expect("the encrypted form takes a password");
        assert_eq!(&encrypted[..8], crate::portable::ENCRYPTED_MAGIC);
        let parsed = crate::portable::parse(&encrypted).expect("it parses");
        assert_eq!(parsed.kind(), crate::portable::PortableKind::EncryptedVault);
        assert!(parsed.vault().is_some());

        assert!(matches!(
            export(&file, ExportFormat::EncryptedVault, None),
            Err(Error::ExportPasswordRequired)
        ));
        assert!(matches!(
            export(&file, ExportFormat::EncryptedVault, Some(b"")),
            Err(Error::ExportPasswordEmpty)
        ));
    }
}
