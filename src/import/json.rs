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

//! The JSON export, plaintext or encrypted.
//!
//! # Shape
//!
//! ```text
//! { "version": 1,
//!   "header": { "slots": …, "params": … },   // both null in a plaintext export
//!   "db": { … } or "<base64 ciphertext>" }
//! ```
//!
//! # One bad entry does not end the import
//!
//! Entries are read one at a time and a failure becomes an [`ImportProblem`]: a single
//! hand-edited or damaged entry must not cost the user the other nine hundred. Only a
//! file-level fault (not JSON, no database, a version this library does not read) stops the
//! whole import.
//!
//! # Unknown fields are ignored
//!
//! That is JSON's own rule and the reference implementation follows it too: a field this reader
//! does not know is not a reason to refuse a file, and the reader must not depend on every
//! version of the exporter writing exactly the fields it knows.

use std::collections::{HashMap, HashSet};

use tinyjson::JsonValue;

use crate::import::mapping::{RawAlgorithm, RawEntry, RawKind, safe_reason};
use crate::import::{
    ImportProblem, ImportReport, ImportedEntry, ImportedGroup, MAX_ENTRIES, drop_duplicates,
};
use crate::import::{MAX_JSON_DEPTH, decode_utf8};
use crate::vault::{GroupId, Timestamp};
use crate::{Error, Result};

/// The highest top-level version this reader accepts.
///
/// Only a **higher** version is refused, which is what the reference implementation does: a lower
/// one is read with the fields it has. The database version inside (`db.version`) is not a reason
/// to refuse anything - it says which fields to expect, and this reader already tolerates missing
/// ones.
const SUPPORTED_VERSION: u64 = 1;

/// Reads a JSON export, encrypted or not.
///
/// `password` is only looked at when the export is encrypted: the database of a plaintext export
/// is an object, and one of an encrypted export is a base64 ciphertext.
///
/// # Errors
///
/// A file-level failure; per-entry failures are in the report.
pub fn import(bytes: &[u8], now: Timestamp, password: Option<&[u8]>) -> Result<ImportReport> {
    check_depth(bytes)?;
    let text = decode_utf8(bytes)?;
    let root: JsonValue = text.parse().map_err(|_| Error::ImportMalformed {
        reason: "the file is not valid JSON",
    })?;
    let document = object(&root).ok_or(Error::ImportMalformed {
        reason: "the JSON document is not an object",
    })?;

    let version = document.get("version").and_then(integer).unwrap_or(0);
    if version > SUPPORTED_VERSION {
        return Err(Error::ImportUnsupportedVersion {
            version,
            supported: SUPPORTED_VERSION,
        });
    }

    let database_value = document.get("db").ok_or(Error::ImportMalformed {
        reason: "the document has no database",
    })?;
    let unlocked = match database_value.get::<String>() {
        // A plaintext export carries the database as an object.
        None => database_value.clone(),
        // An encrypted one carries it as a base64 ciphertext, and the material that opens it sits
        // in the header beside it.
        Some(ciphertext) => {
            let password = password.ok_or(Error::ImportPasswordRequired)?;
            let header = document.get("header").ok_or(Error::ImportMalformed {
                reason: "the encrypted export has no header",
            })?;
            crate::import::encrypted::unlock(ciphertext, header, password)?
        }
    };
    let database = object(&unlocked).ok_or(Error::ImportMalformed {
        reason: "the database is neither an object nor a ciphertext",
    })?;

    read_database(database, now)
}

/// Reads the database object of an export, plaintext or after unlocking.
fn read_database(database: &HashMap<String, JsonValue>, now: Timestamp) -> Result<ImportReport> {
    let groups = read_groups(database.get("groups"));
    let known: HashSet<GroupId> = groups.iter().map(|group| group.id).collect();

    let entries_value = database.get("entries").ok_or(Error::ImportMalformed {
        reason: "the database has no entries",
    })?;
    let entries = array(entries_value).ok_or(Error::ImportMalformed {
        reason: "the entries are not an array",
    })?;
    if entries.len() > MAX_ENTRIES {
        return Err(Error::ImportTooManyEntries {
            limit: MAX_ENTRIES,
            actual: entries.len(),
        });
    }

    let mut report = ImportReport {
        groups,
        ..ImportReport::default()
    };
    for (index, value) in entries.iter().enumerate() {
        let position = index + 1;
        match read_entry(value, &known, now) {
            Ok(imported) => report.entries.push(ImportedEntry {
                groups: imported.groups,
                favorite: imported.favorite,
                position,
                notes: imported.notes,
                entry: imported.entry,
            }),
            Err(error) => report.problems.push(ImportProblem {
                position,
                reason: safe_reason(&error),
            }),
        }
    }

    summarize(&mut report);
    drop_duplicates(&mut report);
    Ok(report)
}

/// An entry with the fields the report needs beside it.
struct Read {
    /// The model entry.
    entry: crate::vault::Entry,
    /// Groups it belonged to.
    groups: Vec<GroupId>,
    /// Whether it was a favourite.
    favorite: bool,
    /// What was dropped or assumed about it.
    notes: Vec<crate::import::ImportNote>,
}

/// Reads one entry of the database.
fn read_entry(value: &JsonValue, known: &HashSet<GroupId>, now: Timestamp) -> Result<Read> {
    let entry = object(value).ok_or(malformed("an entry is not an object"))?;

    let type_name = string(entry, "type").ok_or(malformed("an entry has no type"))?;
    let info = entry
        .get("info")
        .and_then(object)
        .ok_or(malformed("an entry has no information block"))?;

    let secret = string(info, "secret")
        .ok_or(malformed("an entry has no secret"))?
        .to_owned();
    let algorithm = string(info, "algo").map(|name| {
        RawAlgorithm::parse(name).ok_or(malformed(
            "an entry names an algorithm this library does not know",
        ))
    });
    let algorithm = algorithm.transpose()?;
    let digits = match info.get("digits").and_then(integer) {
        None => None,
        Some(count) => Some(u8::try_from(count).map_err(|_| {
            malformed("an entry asks for a code length this library cannot represent")
        })?),
    };
    let kind = read_kind(type_name, info)?;

    let groups: Vec<GroupId> = entry
        .get("groups")
        .and_then(array)
        .map(|values| {
            values
                .iter()
                .filter_map(|value| value.get::<String>())
                .filter_map(|text| parse_group_id(text))
                // A reference to a group the export does not define is dropped: the entry is
                // still imported, it simply belongs to no named group.
                .filter(|id| known.contains(id))
                .collect::<Vec<GroupId>>()
        })
        .unwrap_or_default();

    let favorite = entry
        .get("favorite")
        .and_then(JsonValue::get::<bool>)
        .copied()
        .unwrap_or(false);

    let (icon, icon_problem) = read_icon(entry);
    let (entry, mut notes) = RawEntry {
        name: string(entry, "name").unwrap_or_default().to_owned(),
        issuer: string(entry, "issuer")
            .filter(|text| !text.is_empty())
            .map(str::to_owned),
        note: string(entry, "note").unwrap_or_default().to_owned(),
        secret,
        algorithm,
        digits,
        kind,
        icon,
    }
    .into_entry(now)?;
    if icon_problem {
        notes.push(crate::import::ImportNote::IconDropped);
    }

    Ok(Read {
        entry,
        groups,
        favorite,
        notes,
    })
}

/// Reads an entry's icon, or reports that one was there and could not be kept.
///
/// The shape is another authenticator's: `icon` is the base64 image, `icon_mime` says which of
/// three formats it is, and `icon_hash` is `SHA-256(icon_mime || bytes)` in lowercase hex.
///
/// # A bad picture never costs the entry
///
/// An icon that is not valid base64, has an unknown media type, exceeds the node limit or does
/// not match its hash **drops the icon only** and reports one note. The rest of the entry is a
/// perfectly good 2FA configuration, and refusing it would cost the user the account over a
/// decoration. The hash is not a security check - the file is the user's own export - it only
/// notices a damaged or mismatched picture.
///
/// `(icon, dropped)` where `dropped` is true when there was something that could not be kept.
fn read_icon(entry: &HashMap<String, JsonValue>) -> (Option<crate::vault::EntryIcon>, bool) {
    use crate::vault::{EntryIcon, IconMime};

    let Some(icon_value) = entry.get("icon") else {
        // No field at all: there is no icon to keep.
        return (None, false);
    };
    let Some(encoded) = icon_value.get::<String>() else {
        // `null` (the usual "no icon") is fine; any other type is a damaged field, which costs
        // the icon but not the entry.
        return (None, !icon_value.is_null());
    };
    let Some(bytes) = crate::import::decode_base64(encoded) else {
        return (None, true);
    };
    let mime = entry
        .get("icon_mime")
        .and_then(|value| value.get::<String>())
        .and_then(|text| IconMime::from_media_type(text));
    let Some(mime) = mime else {
        return (None, true);
    };
    let Ok(icon) = EntryIcon::new(mime, bytes) else {
        return (None, true);
    };
    if let Some(expected) = entry
        .get("icon_hash")
        .and_then(|value| value.get::<String>())
        && expected.to_ascii_lowercase() != crate::export::hex(&icon.hash())
    {
        return (None, true);
    }
    (Some(icon), false)
}

/// Reads the per-type parameter block.
fn read_kind(type_name: &str, info: &HashMap<String, JsonValue>) -> Result<RawKind> {
    let period = info.get("period").and_then(integer);
    match type_name.to_ascii_lowercase().as_str() {
        "totp" => Ok(RawKind::Totp { period }),
        "hotp" => {
            let counter = info
                .get("counter")
                .and_then(integer)
                .ok_or(malformed("an HOTP entry has no counter"))?;
            Ok(RawKind::Hotp { counter })
        }
        "steam" => Ok(RawKind::Steam),
        "motp" => Ok(RawKind::Motp {
            period,
            pin: string(info, "pin").map(str::to_owned),
        }),
        "yandex" => Ok(RawKind::Yandex {
            period,
            pin: string(info, "pin").map(str::to_owned),
        }),
        _ => Err(malformed("an entry has a type this library does not know")),
    }
}

/// Reads the group definitions.
///
/// A group without a usable identifier or without a name is skipped: there is nothing to create,
/// and dropping it costs the entries their arrangement, not their existence. The order is the
/// order of the array, which is the order the user arranged the groups in.
fn read_groups(value: Option<&JsonValue>) -> Vec<ImportedGroup> {
    value
        .and_then(array)
        .map(|values| {
            values
                .iter()
                .filter_map(|value| {
                    let group = object(value)?;
                    let id = parse_group_id(string(group, "uuid")?)?;
                    let name = string(group, "name")?.to_owned();
                    Some(ImportedGroup { id, name })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Counts what was dropped, from the notes of every entry.
fn summarize(report: &mut ImportReport) {
    for entry in &report.entries {
        for note in &entry.notes {
            match note {
                crate::import::ImportNote::IconDropped => report.dropped.icons += 1,
                crate::import::ImportNote::PeriodAssumed { .. } => {
                    report.dropped.periods_assumed += 1
                }
            }
        }
    }
}

/// Parses a group identifier: canonical UUID text, with or without dashes.
fn parse_group_id(text: &str) -> Option<GroupId> {
    let mut bytes = [0_u8; GroupId::LEN];
    let mut written = 0;
    let mut high: Option<u8> = None;
    for character in text.chars() {
        if character == '-' {
            continue;
        }
        let value = character.to_digit(16)?;
        #[expect(
            clippy::cast_possible_truncation,
            reason = "to_digit(16) yields at most 15"
        )]
        let value = value as u8;
        match high {
            None => high = Some(value),
            Some(upper) => {
                let byte = bytes.get_mut(written)?;
                *byte = (upper << 4) | value;
                written += 1;
                high = None;
            }
        }
    }
    if high.is_some() || written != GroupId::LEN {
        return None;
    }
    Some(GroupId::from_bytes(bytes))
}

/// Rejects a document that nests too deeply, **before** the parser recurses into it.
///
/// The scan is deliberately naive about JSON grammar and precise about the one thing that
/// matters: it tracks whether it is inside a string, so a brace in a note does not count, and it
/// treats an escape as consuming the next byte, so `\"` does not end the string. Anything the
/// scanner gets wrong can only make the depth look larger, which fails safe.
fn check_depth(bytes: &[u8]) -> Result<()> {
    let mut depth = 0_usize;
    let mut deepest = 0_usize;
    let mut in_string = false;
    let mut escaped = false;

    for &byte in bytes {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                deepest = deepest.max(depth);
                if deepest > MAX_JSON_DEPTH {
                    return Err(Error::ImportTooDeeplyNested {
                        limit: MAX_JSON_DEPTH,
                    });
                }
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    Ok(())
}

/// The object behind a value.
fn object(value: &JsonValue) -> Option<&HashMap<String, JsonValue>> {
    value.get()
}

/// The array behind a value.
fn array(value: &JsonValue) -> Option<&Vec<JsonValue>> {
    value.get()
}

/// A string field of an object.
fn string<'a>(object: &'a HashMap<String, JsonValue>, key: &str) -> Option<&'a str> {
    object.get(key)?.get::<String>().map(String::as_str)
}

/// An integer field: a JSON number that is finite, whole and non-negative.
///
/// A number that is not whole is refused rather than rounded: a counter of `2.5` means the file
/// is not what it claims to be, and rounding it would produce an entry that silently computes
/// different codes from the ones the export shows.
fn integer(value: &JsonValue) -> Option<u64> {
    let number = *value.get::<f64>()?;
    if !number.is_finite() || number < 0.0 {
        return None;
    }
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "the value is finite and non-negative; the comparison below rejects anything a u64 cannot hold"
    )]
    let truncated = number as u64;
    #[expect(
        clippy::cast_precision_loss,
        reason = "comparing back against the original f64 is the whole point of the check"
    )]
    let exact = truncated as f64;
    (exact == number).then_some(truncated)
}

/// A malformed entry, in one phrase.
const fn malformed(reason: &'static str) -> Error {
    Error::ImportMalformed { reason }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::import::ImportFormat;
    use crate::otp::Digits;
    use crate::vault::EntryKind;

    /// A small export in the shape the reference implementation writes.
    const SAMPLE: &str = r#"{
      "version": 1,
      "header": { "slots": null, "params": null },
      "db": {
        "version": 3,
        "entries": [
          { "type": "totp", "uuid": "11111111-1111-1111-1111-111111111111",
            "name": "GitHub", "issuer": "GitHub", "note": "work", "favorite": true,
            "info": { "secret": "JBSWY3DPEHPK3PXP", "algo": "SHA1", "digits": 6, "period": 30 } },
          { "type": "hotp", "uuid": "22222222-2222-2222-2222-222222222222",
            "name": "Bank", "issuer": null, "note": "",
            "info": { "secret": "JBSWY3DPEHPK3PXP", "algo": "SHA256", "digits": 8, "counter": 7 } },
          { "type": "steam", "uuid": "33333333-3333-3333-3333-333333333333",
            "name": "Steam", "issuer": null, "note": "",
            "info": { "secret": "JBSWY3DPEHPK3PXP", "algo": "SHA1", "digits": 5, "period": 30 } },
          { "type": "motp", "uuid": "44444444-4444-4444-4444-444444444444",
            "name": "mOTP", "issuer": "Example", "note": "",
            "info": { "secret": "JBSWY3DPEHPK3PXP", "algo": "MD5", "digits": 6, "period": 10, "pin": "1234" } },
          { "type": "yandex", "uuid": "55555555-5555-5555-5555-555555555555",
            "name": "Yandex", "issuer": null, "note": "",
            "info": { "secret": "LA2V6KMCGYMWWVEW64RNP3JA3I", "algo": "SHA256", "digits": 8, "period": 30, "pin": "1234" } }
        ],
        "groups": [
          { "uuid": "aaaaaaaa-0000-0000-0000-000000000001", "name": "Work" }
        ],
        "icons_optimized": true
      }
    }"#;

    fn import_sample(text: &str) -> ImportReport {
        import(text.as_bytes(), 1_700_000_000, None).expect("the sample is well formed")
    }

    #[test]
    fn every_scheme_in_the_sample_is_read() {
        let report = import_sample(SAMPLE);
        assert!(report.problems.is_empty(), "actual {:?}", report.problems);
        assert_eq!(report.entries.len(), 5);
        assert_eq!(report.groups.len(), 1);
        assert_eq!(report.groups[0].name, "Work");

        let kinds: Vec<&EntryKind> = report
            .entries
            .iter()
            .map(|entry| &entry.entry.kind)
            .collect();
        assert_eq!(kinds[0], &EntryKind::Totp { period: 30 });
        assert_eq!(kinds[1], &EntryKind::Hotp { counter: 7 });
        assert_eq!(kinds[2], &EntryKind::Steam);
        assert_eq!(
            kinds[3],
            &EntryKind::Motp {
                period: 10,
                pin: Some(crate::motp::MotpPin::new("1234".to_owned()))
            }
        );
        assert_eq!(
            kinds[4],
            &EntryKind::Yandex {
                period: 30,
                pin: Some(crate::yaotp::YandexPin::new("1234".to_owned()))
            }
        );

        assert_eq!(report.entries[0].entry.digits, Digits::SIX);
        assert_eq!(report.entries[1].entry.digits, Digits::EIGHT);
        assert_eq!(report.entries[2].entry.digits, Digits::FIVE);
        assert!(report.entries[0].favorite);
        assert!(!report.entries[1].favorite);
        assert_eq!(report.entries[0].entry.note, "work");
        assert_eq!(report.entries[0].entry.issuer.as_deref(), Some("GitHub"));
        assert_eq!(
            report.entries[1].entry.issuer, None,
            "a null issuer is no issuer"
        );
        assert_eq!(
            report.entries[4].entry.issuer.as_deref(),
            Some("Yandex"),
            "the scheme names itself when the export does not"
        );
    }

    #[test]
    fn an_entry_carries_the_groups_it_names() {
        let mut text = String::from(SAMPLE);
        // Give the first entry the group the database defines.
        text = text.replace(
            r#""name": "GitHub", "issuer": "GitHub", "note": "work", "favorite": true,"#,
            r#""name": "GitHub", "issuer": "GitHub", "note": "work", "favorite": true,
            "groups": ["aaaaaaaa-0000-0000-0000-000000000001", "bbbbbbbb-0000-0000-0000-000000000002"],"#,
        );
        let report = import_sample(&text);
        assert!(report.problems.is_empty(), "actual {:?}", report.problems);
        assert_eq!(
            report.entries[0].groups,
            vec![report.groups[0].id],
            "a reference to a group the file does not define is dropped"
        );
        assert!(report.entries[1].groups.is_empty());
    }

    #[test]
    fn one_bad_entry_does_not_end_the_import() {
        let text = SAMPLE.replace(
            r#""algo": "SHA1", "digits": 6, "period": 30"#,
            r#""algo": "SHA1", "digits": 10, "period": 30"#,
        );
        let report = import_sample(&text);

        assert_eq!(report.entries.len(), 4, "the other entries still arrive");
        assert_eq!(report.problems.len(), 1);
        assert_eq!(report.problems[0].position, 1);
        assert!(
            report.problems[0].reason.contains("31 bits"),
            "the reason must say why ten digits cannot be produced: {}",
            report.problems[0].reason
        );
    }

    /// A well-formed icon is kept, and no note is reported for it.
    #[test]
    fn a_valid_icon_is_kept() {
        let text = SAMPLE.replace(
            r#""favorite": true,"#,
            r#""favorite": true, "icon": "iVBORw0KGgo=", "icon_mime": "image/png","#,
        );
        let report = import_sample(&text);
        assert_eq!(report.entries.len(), 5);
        assert_eq!(report.dropped.icons, 0);
        let icon = report.entries[0]
            .entry
            .icon
            .as_ref()
            .expect("the icon is kept");
        assert_eq!(icon.mime, crate::vault::IconMime::Png);
        assert_eq!(&icon.bytes[..4], b"\x89PNG");
        assert!(!report.entries[0].has_notes());
    }

    /// A damaged icon is dropped and counted; the entry itself is still imported.
    #[test]
    fn a_bad_icon_costs_the_icon_not_the_entry() {
        for (replacement, why) in [
            (
                r#""favorite": true, "icon": "not base64!", "icon_mime": "image/png","#,
                "the icon is not base64",
            ),
            (
                r#""favorite": true, "icon": "AAAA", "icon_mime": "image/webp","#,
                "the media type is not one this library stores",
            ),
            (
                r#""favorite": true, "icon": "AAAA","#,
                "there is no media type at all",
            ),
        ] {
            let text = SAMPLE.replace(r#""favorite": true,"#, replacement);
            let report = import_sample(&text);
            assert_eq!(report.entries.len(), 5, "{why}");
            assert_eq!(report.dropped.icons, 1, "{why}");
            assert!(report.entries[0].has_notes(), "{why}");
            assert!(report.entries[0].entry.icon.is_none(), "{why}");
        }
    }

    /// A hash that does not match the bytes drops the icon, and a matching one keeps it.
    #[test]
    fn the_icon_hash_is_checked_when_present() {
        let bytes = b"\x89PNG fixture";
        let encoded = crate::export::base64(bytes);
        let icon = crate::vault::EntryIcon::new(crate::vault::IconMime::Png, bytes.to_vec())
            .expect("small icon");
        let matching = crate::export::hex(&icon.hash());
        let good = SAMPLE.replace(
            r#""favorite": true,"#,
            &format!(
                r#""favorite": true, "icon": "{encoded}", "icon_mime": "image/png", "icon_hash": "{matching}","#
            ),
        );
        let report = import_sample(&good);
        assert_eq!(report.dropped.icons, 0);
        assert!(report.entries[0].entry.icon.is_some());

        let wrong = SAMPLE.replace(
            r#""favorite": true,"#,
            &format!(
                r#""favorite": true, "icon": "{encoded}", "icon_mime": "image/png", "icon_hash": "{}","#,
                "00".repeat(32)
            ),
        );
        let report = import_sample(&wrong);
        assert_eq!(report.dropped.icons, 1);
        assert!(
            report.entries[0].entry.icon.is_none(),
            "a hash that does not match means the picture is not the one the file describes"
        );
    }

    #[test]
    fn a_higher_version_is_refused_but_a_lower_one_is_read() {
        let result = import(
            SAMPLE
                .replace(r#""version": 1,"#, r#""version": 2,"#)
                .as_bytes(),
            0,
            None,
        );
        assert!(
            matches!(
                result,
                Err(Error::ImportUnsupportedVersion { version: 2, .. })
            ),
            "actual {result:?}"
        );

        // The database version is not a reason to refuse anything.
        let report = import_sample(&SAMPLE.replace(r#""version": 3,"#, r#""version": 99,"#));
        assert_eq!(report.entries.len(), 5);
    }

    #[test]
    fn an_encrypted_database_asks_for_a_password() {
        let text = r#"{"version":1,"header":{"slots":[],"params":{}},"db":"AAAA"}"#;
        let result = import(text.as_bytes(), 0, None);
        assert!(
            matches!(result, Err(Error::ImportPasswordRequired)),
            "actual {result:?}"
        );
    }

    #[test]
    fn structural_faults_are_file_level_failures() {
        for (text, expected) in [
            ("not json at all", "not valid JSON"),
            ("[]", "not an object"),
            (r#"{"version":1}"#, "no database"),
            (r#"{"version":1,"db":{}}"#, "no entries"),
        ] {
            let result = import(text.as_bytes(), 0, None);
            match result {
                Err(Error::ImportMalformed { reason }) => assert!(
                    reason.contains(expected),
                    "the reason for {text} should say {expected}, actual {reason}"
                ),
                other => panic!("{text} should be a file-level failure, actual {other:?}"),
            }
        }
    }

    #[test]
    fn a_deeply_nested_document_is_refused_before_it_is_parsed() {
        let depth = MAX_JSON_DEPTH + 5;
        let text = format!("{}{}", "[".repeat(depth), "]".repeat(depth));
        let result = import(text.as_bytes(), 0, None);
        assert!(
            matches!(result, Err(Error::ImportTooDeeplyNested { .. })),
            "actual {result:?}"
        );

        // Braces inside a string do not count, and neither does an escaped quote.
        let text = format!(
            r#"{{"version":1,"db":{{"entries":[],"groups":[],"note":"{}"}}}}"#,
            "[".repeat(depth)
        );
        assert!(
            import(text.as_bytes(), 0, None).is_ok(),
            "brackets inside a string are content, not nesting"
        );
    }

    #[test]
    fn the_detected_format_is_json() {
        assert_eq!(
            ImportFormat::detect(SAMPLE.as_bytes()),
            Some(ImportFormat::Json)
        );
    }
}
