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

//! Reading entries from another authenticator's export.
//!
//! The reader answers one question: **what does this file say?** It performs no I/O, touches no
//! vault and reads no clock - the caller passes the current time, as everywhere else in this
//! crate. The output is a [`ImportReport`]: the entries that could be read, the groups they
//! belong to, and what was skipped or dropped on the way.
//!
//! # Two kinds of failure, deliberately separated
//!
//! A **file-level** failure returns an [`Error`]: the bytes are not the format they claim to be,
//! the file is larger than this reader accepts, the version is one it does not read, or the
//! password does not open an encrypted export. Nothing can be salvaged, and the caller has
//! nothing to show.
//!
//! An **entry-level** failure is a [`ImportProblem`]: one entry names a secret that is not
//! Base32, or asks for a code length this library refuses. The other entries are still imported,
//! and the problem list says which ones did not make it and why - which is what a user needs to
//! fix the source and try again.
//!
//! # Secrets do not appear in the report
//!
//! [`ImportProblem`] carries a position and a reason, never a value: a problem list ends up in a
//! log, in a screenshot attached to a bug report, and in a crash dump. The same rule the rest of
//! the crate follows applies here before the data has even entered the model.
//!
//! # The second half of an import
//!
//! Reading a file is only half of it: what the entries mean for the vault already there - which
//! are new, which the vault holds, and which need a human to decide - is the `apply` module, which
//! is the only part of this module tree that needs a vault.
//!
//! # Encrypted exports
//!
//! The JSON export can be encrypted, and is then opened with a password the caller supplies. The
//! two stages of that unlocking, and the bound every parameter it reads is held to before it
//! decides how much memory and time to spend, are in the `encrypted` module. Without a password an
//! encrypted export returns [`Error::ImportPasswordRequired`] rather than an empty report, so a
//! caller cannot mistake "this needs a password" for "there was nothing to import".

pub mod apply;
mod encrypted;
pub mod html;
pub mod json;
mod mapping;
mod png;

// The image column of an HTML export is the only place a time step is written down, and reading it
// is a self-contained job: a PNG in, the text of the code it draws out. It is public because a
// caller that has the document can do the same thing with one column of it.
pub use png::{PngError, qr_text_from_png};
pub mod text;

use crate::vault::Timestamp;
use crate::{Error, Result};

/// The largest export this reader accepts: 8 MiB.
///
/// A vault of ten thousand entries with long notes is a few megabytes; anything beyond this is
/// not a vault, and the number is compared **before** the bytes are parsed or copied.
pub const MAX_EXPORT_BYTES: usize = 8 * 1024 * 1024;

/// The largest number of entries this reader accepts.
pub const MAX_ENTRIES: usize = 10_000;

/// The deepest JSON nesting this reader accepts.
///
/// The JSON parser recurses, so the depth is checked by scanning the bytes first; see
/// [`Error::ImportTooDeeplyNested`]. Real exports nest four levels at most (document, database,
/// entry, information), so the limit costs nothing and removes a way to take the process down.
pub const MAX_JSON_DEPTH: usize = 32;

/// An export format this reader understands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportFormat {
    /// The JSON export, encrypted or not.
    Json,
    /// The HTML export: one table row per entry.
    Html,
    /// The text export: one URI per line.
    Text,
}

impl ImportFormat {
    /// The name used in messages and diagnostics.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Json => "JSON",
            Self::Html => "HTML",
            Self::Text => "text",
        }
    }

    /// Guesses the format from the content, returning `None` when it is not recognisable.
    ///
    /// **The content decides, not the file name**: a file picked from a downloads directory can
    /// be named anything, and an export is identified by what is inside it. A caller that has
    /// already asked the user which format it is may skip this and pass the format directly.
    #[must_use]
    pub fn detect(bytes: &[u8]) -> Option<Self> {
        let text = core::str::from_utf8(bytes).ok()?;
        let trimmed = text.trim_start_matches(['\u{feff}', ' ', '\t', '\r', '\n']);

        if trimmed.starts_with('{') {
            return Some(Self::Json);
        }
        if trimmed.starts_with("otpauth://") || trimmed.starts_with("motp:") {
            return Some(Self::Text);
        }
        let lower = trimmed.to_ascii_lowercase();
        if lower.starts_with("<!doctype html")
            || lower.contains("<html")
            || lower.contains("<table")
        {
            return Some(Self::Html);
        }
        None
    }
}

/// One entry read from an export.
#[derive(Debug)]
pub struct ImportedEntry {
    /// The entry, ready to be inserted into a vault.
    ///
    /// Its identifier is **new**: the export's own identifier for the entry is not reused, since
    /// reusing it would mean two devices that imported the same export hold the same identifier
    /// for entries that are not the same entry. Group identifiers *are* reused - see
    /// [`ImportedEntry::groups`].
    pub entry: crate::vault::Entry,
    /// The groups this entry belonged to, in the order the export listed them.
    pub groups: Vec<crate::vault::GroupId>,
    /// Whether the export marked it as a favourite.
    ///
    /// Not a field of the entry: a favourite is an arrangement, and the caller put it into the
    /// ordering (favourites first) when it applies the report.
    pub favorite: bool,
    /// Where in the export this entry was, counting from 1.
    pub position: usize,
    /// What was dropped or assumed while reading it.
    pub notes: Vec<ImportNote>,
}

impl ImportedEntry {
    /// Whether anything about this entry was dropped or assumed.
    #[must_use]
    pub fn has_notes(&self) -> bool {
        !self.notes.is_empty()
    }
}

/// A group the export defined.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedGroup {
    /// The group's identifier, taken from the export so that two devices importing the same file
    /// agree on which group is which.
    pub id: crate::vault::GroupId,
    /// The name the export gave it.
    pub name: String,
}

/// Something dropped or assumed about one entry.
///
/// Reported per entry so the preview can mark the row, and counted in [`DroppedSummary`] so the
/// interface can say it once instead of interrupting per entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportNote {
    /// The export carried an icon that could not be kept: not valid base64, a media type this
    /// library does not store, larger than one vault node, or not matching its own hash.
    ///
    /// The icon is dropped and the entry is kept: a damaged picture must not cost the user an
    /// account they can still compute codes for.
    IconDropped,
    /// The format has no time step, so the default was assumed.
    ///
    /// Reported rather than applied silently: a period that is not the default produces codes
    /// that never match, and nothing in the entry would say why.
    PeriodAssumed {
        /// The step that was assumed, in seconds.
        seconds: u64,
    },
}

/// How much was dropped across the whole export.
///
/// One summary for the interface to show in a single sentence, next to whatever else the import
/// skipped. Nothing here needs the user to act, which is why it is a count and not a list.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DroppedSummary {
    /// Entries whose icon was dropped.
    pub icons: usize,
    /// Entries whose time step was assumed.
    pub periods_assumed: usize,
    /// Entries skipped because an identical entry had already been read from the same export.
    pub duplicates: usize,
}

/// One entry that could not be read.
///
/// Carries a position and a reason **and nothing else**: see the module documentation for why no
/// value from the export may appear here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportProblem {
    /// Where in the export the entry was, counting from 1.
    pub position: usize,
    /// Why it was skipped, in one phrase.
    pub reason: String,
}

/// Everything the reader found in an export.
#[derive(Debug, Default)]
pub struct ImportReport {
    /// Entries that could be read, in the order the export listed them.
    pub entries: Vec<ImportedEntry>,
    /// Groups the export defined, in the order it listed them.
    pub groups: Vec<ImportedGroup>,
    /// Entries that could not be read, each with its position and a reason.
    pub problems: Vec<ImportProblem>,
    /// What was dropped or assumed, counted.
    pub dropped: DroppedSummary,
}

impl ImportReport {
    /// Whether the export yielded nothing at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Checks the size of an export before anything else looks at it.
    ///
    /// # Errors
    ///
    /// [`Error::ImportFileTooLarge`] when the input exceeds [`MAX_EXPORT_BYTES`].
    pub(crate) fn check_size(bytes: &[u8]) -> Result<()> {
        if bytes.len() > MAX_EXPORT_BYTES {
            return Err(Error::ImportFileTooLarge {
                limit: MAX_EXPORT_BYTES,
                actual: bytes.len(),
            });
        }
        Ok(())
    }
}

/// Reads an export.
///
/// `format` is what the caller believes the file is; [`ImportFormat::detect`] answers that
/// question from the content when the caller does not know. `now` is the current Unix second
/// supplied by the caller (this library reads no clock) and becomes the creation and modification
/// time of every imported entry. `password` is the UTF-8 bytes of the export's password, which
/// only an encrypted export looks at: the derivation consumes bytes, and hashing text would mean
/// choosing a normalization the format does not specify.
///
/// # Errors
///
/// A file-level failure: see the module documentation for the split between this and
/// [`ImportProblem`].
pub fn import(
    bytes: &[u8],
    format: ImportFormat,
    now: Timestamp,
    password: Option<&[u8]>,
) -> Result<ImportReport> {
    ImportReport::check_size(bytes)?;
    match format {
        ImportFormat::Json => json::import(bytes, now, password),
        ImportFormat::Text => text::import(bytes, now),
        ImportFormat::Html => html::import(bytes, now),
    }
}

/// Drops entries that repeat an earlier one **exactly**.
///
/// Two entries that agree in every field are the same entry imported twice - the same export
/// listed it twice, or the user picked the same file twice - and keeping both would fill the
/// interface with identical rows that the user then has to delete one by one. The first one is
/// kept and the count goes into [`DroppedSummary::duplicates`], so the interface can say it in
/// the same sentence as the rest.
///
/// Entries that differ in **any** field are left alone, even when they share a secret: "the same
/// account with a different name" is a question for the user (keep the existing one, replace it,
/// or keep both), and the importer is not the place to answer it. See the duplicate rules in the
/// project plan.
///
/// The comparison is bucketed by the secret-free `Debug` of the entry, so the constant-time secret
/// comparison runs only between entries that already agree on everything else.
pub(crate) fn drop_duplicates(report: &mut ImportReport) {
    let mut buckets: std::collections::HashMap<String, Vec<usize>> =
        std::collections::HashMap::new();
    let mut kept: Vec<ImportedEntry> = Vec::with_capacity(report.entries.len());

    for entry in report.entries.drain(..) {
        let bucket = buckets.entry(format!("{:?}", entry.entry)).or_default();
        if bucket.iter().any(|index| kept[*index].entry == entry.entry) {
            report.dropped.duplicates += 1;
            continue;
        }
        bucket.push(kept.len());
        kept.push(entry);
    }
    report.entries = kept;
}

/// Decodes standard base64 (RFC 4648 §4), or `None` when the text is not that.
///
/// The alphabet is the standard one (`+` and `/`), padding is present, and no whitespace is
/// written; anything outside that is refused rather than skipped, since a decoder that tolerates
/// extra characters turns a modified file into a shorter one. One decoder serves both callers
/// (the encrypted database and an entry's icon) so that the two cannot disagree about what a
/// valid encoding is.
pub(crate) fn decode_base64(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    let chunks = bytes.len() / 4;
    if !bytes.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(chunks * 3);

    for (index_of_chunk, chunk) in bytes.chunks(4).enumerate() {
        let mut values = [0_u8; 4];
        let mut padding = 0_usize;
        for (index, byte) in chunk.iter().enumerate() {
            if *byte == b'=' {
                padding += 1;
                continue;
            }
            if padding > 0 {
                // A character after padding means the padding is not at the end of its chunk.
                return None;
            }
            values[index] = base64_value(*byte)?;
        }
        // Padding can only end the **last** chunk, and at most two characters of it can be
        // padding: anything else decodes to a string that was never encoded this way.
        if padding > 2 || (padding > 0 && index_of_chunk + 1 != chunks) {
            return None;
        }

        let bits = (u32::from(values[0]) << 18)
            | (u32::from(values[1]) << 12)
            | (u32::from(values[2]) << 6)
            | u32::from(values[3]);
        out.push((bits >> 16) as u8);
        if padding < 2 {
            out.push((bits >> 8) as u8);
        }
        if padding == 0 {
            out.push(bits as u8);
        }
    }
    Some(out)
}

/// The value of one base64 character.
const fn base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Decodes an export as UTF-8.
///
/// # Why the declaration is not consulted
///
/// Every export this reader accepts is written as UTF-8 by the implementation that produces it:
/// the JSON is UTF-8 by definition, the text export is written line by line, and the HTML export
/// carries **no** charset declaration at all. Trusting a declaration inside the HTML would mean
/// believing attacker-controlled bytes about how to read attacker-controlled bytes, and the
/// second reading is the one that would be wrong.
///
/// # Errors
///
/// [`Error::ImportMalformed`] when the bytes are not valid UTF-8.
pub(crate) fn decode_utf8(bytes: &[u8]) -> Result<&str> {
    core::str::from_utf8(bytes).map_err(|_| Error::ImportMalformed {
        reason: "the file is not valid UTF-8",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detection_reads_the_content_not_the_name() {
        assert_eq!(
            ImportFormat::detect(br#"{"version":1}"#),
            Some(ImportFormat::Json)
        );
        assert_eq!(
            ImportFormat::detect(b"otpauth://totp/a?secret=JBSWY3DPEHPK3PXP"),
            Some(ImportFormat::Text)
        );
        assert_eq!(
            ImportFormat::detect(b"motp:/a?secret=deadbeef"),
            Some(ImportFormat::Text)
        );
        assert_eq!(
            ImportFormat::detect(b"<!DOCTYPE html>\n<html><body></body></html>"),
            Some(ImportFormat::Html)
        );
        assert_eq!(ImportFormat::detect(b"nonsense"), None);
        assert_eq!(ImportFormat::detect(&[0xFF, 0xFE]), None);
    }

    #[test]
    fn detection_skips_a_byte_order_mark_and_leading_space() {
        assert_eq!(
            ImportFormat::detect("\u{feff}  \r\n otpauth://totp/a?secret=AA".as_bytes()),
            Some(ImportFormat::Text)
        );
        assert_eq!(
            ImportFormat::detect(b"\n\n  {\"version\":1}"),
            Some(ImportFormat::Json)
        );
    }

    #[test]
    fn an_oversized_export_is_refused_before_it_is_read() {
        let bytes = vec![0_u8; MAX_EXPORT_BYTES + 1];
        let result = import(&bytes, ImportFormat::Json, 0, None);
        assert!(
            matches!(result, Err(Error::ImportFileTooLarge { .. })),
            "actual {result:?}"
        );
    }

    /// An entry the export lists twice is kept once; an entry that differs in any field is a
    /// question for the user, not for the importer.
    #[test]
    fn an_entry_repeated_in_the_export_is_kept_once() {
        let text = "otpauth://totp/a?secret=JBSWY3DPEHPK3PXP\n\
                    otpauth://totp/a?secret=JBSWY3DPEHPK3PXP\n\
                    otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&digits=8\n";
        let report = import(text.as_bytes(), ImportFormat::Text, 1_700_000_000, None)
            .expect("the text is valid UTF-8");

        assert_eq!(
            report.entries.len(),
            2,
            "the exact repeat is dropped and the differing entry is kept"
        );
        assert_eq!(report.dropped.duplicates, 1);
        assert_eq!(report.entries[1].entry.digits, crate::otp::Digits::EIGHT);
    }
}
