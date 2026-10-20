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
//!   "header": { "slots": null, "params": null },   // both null in a plaintext export
//!   "db": { … } or "<base64 ciphertext>" }
//! ```
//!
//! The database holds `version`, `entries[]`, `groups[]` and `icons_optimized`. Every entry
//! carries `type`, `uuid`, `name`, `issuer`, `note`, `favorite`, `icon`, `info` and `groups`;
//! `info` holds the secret, the algorithm, the digit count and whatever belongs to the scheme
//! (a step, a counter, a PIN).
//!
//! # Two stages of encryption, exactly as the reader opens them
//!
//! The password does not encrypt the database. It derives a key that opens a **slot**, the slot
//! holds the master key, and the master key encrypts the database:
//!
//! - the slot's master key, and the database's own nonce, are random;
//! - the password is stretched with scrypt (cost 2^15, block size 8, parallelisation 1, a 32-byte
//!   salt) and the result encrypts the master key with AES-256-GCM;
//! - the database is encrypted with the master key, AES-256-GCM as well, with no associated data;
//! - the format stores the tag **beside** the ciphertext (as a hexadecimal `tag` field) rather
//!   than appended to it, which is why every sealed value is split in two here.
//!
//! The two derived keys are erased as soon as they have been used
//! ([`secrecy::zeroize::Zeroize`]); the ciphertext stays.
//!
//! # One slot, and it is a password slot
//!
//! The reader accepts three kinds of slot and honours only the password one. This writer emits
//! exactly one slot, of that kind: there is no platform key store here, and a biometric slot
//! would be a promise this library cannot keep on the machine that reads the file next.
//!
//! # The numbers are written as integers, and this writer is hand-written because of it
//!
//! The JSON crate this library reads with holds every number as an `f64`, which cannot represent
//! an HOTP counter above 2^53 exactly: writing one through it would round the value and produce
//! an export whose codes differ from the vault's. The writer below is therefore its own small
//! piece of code - and it is also what keeps this crate free of `std::io`, which the reader's
//! generator would have pulled in.

use aes_gcm::aead::{AeadInOut, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use secrecy::zeroize::Zeroize;

use crate::Result;
use crate::export::{Item, algorithm_name, base64, hex, items, named_groups, type_name, uuid_text};
use crate::vault::{EntryKind, Vault};

/// The version of the document this writer produces.
const FORMAT_VERSION: u64 = 1;

/// The version of the database object, which says which fields to expect.
const DATABASE_VERSION: u64 = 3;

/// The slot kind a password opens.
const SLOT_PASSWORD: u64 = 1;

/// The scrypt cost parameter, as the number of iterations (2^15).
const KDF_COST: u64 = 1 << 15;

/// The scrypt cost parameter's base-2 logarithm, which is the form scrypt takes.
const KDF_LOG_N: u8 = 15;

/// The scrypt block size.
const KDF_BLOCK_SIZE: u32 = 8;

/// The scrypt parallelisation.
const KDF_PARALLELISM: u32 = 1;

/// The length of the salt, in bytes.
const SALT_LEN: usize = 32;

/// The length of an AES-256-GCM key, in bytes.
const KEY_LEN: usize = 32;

/// The length of the AES-256-GCM nonce, in bytes.
const NONCE_LEN: usize = 12;

/// The length of the AES-256-GCM tag, in bytes.
const TAG_LEN: usize = 16;

/// Writes the vault as a plaintext JSON export.
///
/// # Errors
///
/// A field the format cannot represent: see [`crate::export::export`].
pub fn write(vault: &Vault) -> Result<String> {
    let mut json = Json::new();
    json.begin_object();
    json.key("version");
    json.integer(FORMAT_VERSION);
    json.key("header");
    json.begin_object();
    json.key("slots");
    json.null();
    json.key("params");
    json.null();
    json.end_object();
    json.key("db");
    database_into(&mut json, vault)?;
    json.end_object();
    Ok(json.into_text())
}

/// Writes the vault as an encrypted JSON export.
///
/// `password` is the UTF-8 bytes of the password; nothing in the file is readable without it.
///
/// # Errors
///
/// A field the format cannot represent, or [`crate::Error::RandomnessUnavailable`] when the
/// operating system's random source is unavailable - the salt, the master key and both nonces
/// come from it, and none of them may come from a userspace generator.
pub fn write_encrypted(vault: &Vault, password: &[u8]) -> Result<String> {
    // The database is built as its own document and then encrypted as a whole: the plaintext
    // export writes the very same object, so the two formats cannot drift apart.
    let mut database = Json::new();
    database_into(&mut database, vault)?;

    let mut salt = [0_u8; SALT_LEN];
    let mut master = [0_u8; KEY_LEN];
    let mut slot_uuid = [0_u8; 16];
    for buffer in [&mut salt[..], &mut master[..], &mut slot_uuid[..]] {
        crate::getrandom::fill(buffer).map_err(|_| crate::Error::RandomnessUnavailable)?;
    }

    let parameters =
        scrypt::Params::new(KDF_LOG_N, KDF_BLOCK_SIZE, KDF_PARALLELISM).map_err(|_| {
            crate::Error::ExportParameterRefused {
                parameter: "scrypt cost, block size and parallelisation",
            }
        })?;
    let mut derived = [0_u8; KEY_LEN];
    scrypt::scrypt(password, &salt, &parameters, &mut derived).map_err(|_| {
        crate::Error::ExportParameterRefused {
            parameter: "scrypt output length",
        }
    })?;

    let slot = seal(&derived, &master)?;
    derived.zeroize();
    let sealed = seal(&master, database.into_text().as_bytes())?;
    master.zeroize();

    let (slot_nonce, slot_tag, slot_key) = slot;
    let (db_nonce, db_tag, db_ciphertext) = sealed;

    let mut json = Json::new();
    json.begin_object();
    json.key("version");
    json.integer(FORMAT_VERSION);
    json.key("header");
    json.begin_object();
    json.key("slots");
    json.begin_array();
    json.begin_object();
    json.key("type");
    json.integer(SLOT_PASSWORD);
    json.key("uuid");
    json.string(&uuid_text(&slot_uuid));
    json.key("key");
    json.string(&hex(&slot_key));
    json.key("key_params");
    json.begin_object();
    json.key("nonce");
    json.string(&hex(&slot_nonce));
    json.key("tag");
    json.string(&hex(&slot_tag));
    json.end_object();
    json.key("n");
    json.integer(KDF_COST);
    json.key("r");
    json.integer(u64::from(KDF_BLOCK_SIZE));
    json.key("p");
    json.integer(u64::from(KDF_PARALLELISM));
    json.key("salt");
    json.string(&hex(&salt));
    // The two fields the format carries for a slot that was repaired from a backup. This writer
    // never does either, and writing `false` is what makes that sayable rather than absent.
    json.key("repaired");
    json.boolean(false);
    json.key("is_backup");
    json.boolean(false);
    json.end_object();
    json.end_array();
    json.key("params");
    json.begin_object();
    json.key("nonce");
    json.string(&hex(&db_nonce));
    json.key("tag");
    json.string(&hex(&db_tag));
    json.end_object();
    json.end_object();
    json.key("db");
    json.string(&base64(&db_ciphertext));
    json.end_object();
    Ok(json.into_text())
}

/// Encrypts one section, returning its nonce, its tag and the ciphertext without the tag.
fn seal(
    key: &[u8; KEY_LEN],
    plaintext: &[u8],
) -> Result<([u8; NONCE_LEN], [u8; TAG_LEN], Vec<u8>)> {
    let mut nonce = [0_u8; NONCE_LEN];
    crate::getrandom::fill(&mut nonce).map_err(|_| crate::Error::RandomnessUnavailable)?;

    let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(*key));
    let mut buffer = plaintext.to_vec();
    cipher
        .encrypt_in_place(&Nonce::from(nonce), &[], &mut buffer)
        .map_err(|_| crate::Error::ExportTooLarge)?;

    // The AEAD appends the tag to the ciphertext; the format keeps the two apart, so they are
    // split here rather than at every call site.
    let tag: [u8; TAG_LEN] = buffer
        .split_off(buffer.len().saturating_sub(TAG_LEN))
        .try_into()
        .map_err(|_| crate::Error::ExportParameterRefused {
            parameter: "AES-GCM tag length",
        })?;
    Ok((nonce, tag, buffer))
}

/// Writes the database object of an export.
fn database_into(json: &mut Json, vault: &Vault) -> Result<()> {
    json.begin_object();
    json.key("version");
    json.integer(DATABASE_VERSION);
    json.key("entries");
    json.begin_array();
    for item in items(vault) {
        entry_into(json, &item)?;
    }
    json.end_array();
    json.key("groups");
    json.begin_array();
    for (id, group) in named_groups(vault) {
        json.begin_object();
        json.key("uuid");
        json.string(&uuid_text(id.as_bytes()));
        json.key("name");
        json.string(&group.name);
        json.end_object();
    }
    json.end_array();
    json.key("icons_optimized");
    json.boolean(false);
    json.end_object();
    Ok(())
}

/// Writes one entry.
fn entry_into(json: &mut Json, item: &Item<'_>) -> Result<()> {
    let entry = item.entry;

    json.begin_object();
    json.key("type");
    json.string(type_name(&entry.kind));
    json.key("uuid");
    json.string(&uuid_text(item.id.as_bytes()));
    json.key("name");
    json.string(&entry.name);
    json.key("issuer");
    match entry.issuer.as_deref() {
        Some(issuer) => json.string(issuer),
        None => json.null(),
    }
    json.key("note");
    json.string(&entry.note);
    // This application has no favourites: the ordering says what the user put where, and a
    // favourite flag no interface reads would come back as an arrangement change.
    json.key("favorite");
    json.boolean(false);
    // The icon is written as the original bytes, exactly as the reference format keeps them.
    // `icon_mime` and `icon_hash` accompany it; `icon_hash` is computed here rather than stored,
    // so it cannot drift from the bytes. An entry with no icon writes `null`, which is what the
    // reference implementation writes too.
    json.key("icon");
    match &entry.icon {
        Some(icon) => json.string(&base64(&icon.bytes)),
        None => json.null(),
    }
    if let Some(icon) = &entry.icon {
        json.key("icon_mime");
        json.string(icon.mime.media_type());
        json.key("icon_hash");
        json.string(&hex(&icon.hash()));
    }

    json.key("info");
    json.begin_object();
    json.key("secret");
    json.string(&entry.secret.to_base32());
    json.key("algo");
    json.string(algorithm_name(&entry.kind, entry.algorithm));
    json.key("digits");
    json.integer(u64::from(entry.digits.count()));
    match &entry.kind {
        EntryKind::Totp { period } => {
            json.key("period");
            json.integer(*period);
        }
        EntryKind::Hotp { counter } => {
            json.key("counter");
            json.integer(*counter);
        }
        EntryKind::Steam => {
            // Steam Guard's step is fixed by the scheme and is not stored, but the format has a
            // period field for it and a reader that wants one finds the value the scheme uses.
            json.key("period");
            json.integer(crate::otp::STEAM_PERIOD);
        }
        EntryKind::Motp { period, pin } => {
            json.key("period");
            json.integer(*period);
            if let Some(pin) = pin {
                json.key("pin");
                json.string(pin.expose());
            }
        }
        EntryKind::Yandex { period, pin } => {
            json.key("period");
            json.integer(*period);
            if let Some(pin) = pin {
                json.key("pin");
                json.string(pin.expose());
            }
        }
    }
    json.end_object();

    json.key("groups");
    json.begin_array();
    if let Some(group) = item.group {
        json.string(&uuid_text(group.as_bytes()));
    }
    json.end_array();
    json.end_object();
    Ok(())
}

/// A JSON writer: values appended to a string, no I/O and no number type of its own.
///
/// Integers are written from `u64` directly, which is the reason this exists rather than the
/// generator of the crate this library reads JSON with (see the module documentation).
struct Json {
    /// The document being built.
    out: String,
    /// The number of members written in each open object or array. The one on top decides
    /// whether the next member needs a comma.
    open: Vec<usize>,
    /// Whether the last thing written was a key, whose value must not be preceded by a comma
    /// (the key already wrote one).
    after_key: bool,
}

impl Json {
    /// An empty document.
    fn new() -> Self {
        Self {
            out: String::new(),
            open: Vec::new(),
            after_key: false,
        }
    }

    /// The finished text.
    fn into_text(self) -> String {
        self.out
    }

    /// Writes whatever a value needs before it: a comma unless it is the first member or the
    /// value of a key.
    fn separate(&mut self) {
        if self.after_key {
            self.after_key = false;
            return;
        }
        if let Some(count) = self.open.last_mut() {
            if *count > 0 {
                self.out.push(',');
            }
            *count += 1;
        }
    }

    /// Opens an object.
    fn begin_object(&mut self) {
        self.separate();
        self.out.push('{');
        self.open.push(0);
    }

    /// Closes the object most recently opened.
    fn end_object(&mut self) {
        self.open.pop();
        self.out.push('}');
    }

    /// Opens an array.
    fn begin_array(&mut self) {
        self.separate();
        self.out.push('[');
        self.open.push(0);
    }

    /// Closes the array most recently opened.
    fn end_array(&mut self) {
        self.open.pop();
        self.out.push(']');
    }

    /// Writes a member name. The value that follows it must not write a comma of its own.
    fn key(&mut self, name: &str) {
        if let Some(count) = self.open.last_mut() {
            if *count > 0 {
                self.out.push(',');
            }
            *count += 1;
        }
        self.quote(name);
        self.out.push(':');
        self.after_key = true;
    }

    /// Writes a string value.
    fn string(&mut self, value: &str) {
        self.separate();
        self.quote(value);
    }

    /// Writes a whole number.
    fn integer(&mut self, value: u64) {
        self.separate();
        self.out.push_str(&value.to_string());
    }

    /// Writes `true` or `false`.
    fn boolean(&mut self, value: bool) {
        self.separate();
        self.out.push_str(if value { "true" } else { "false" });
    }

    /// Writes `null`.
    fn null(&mut self) {
        self.separate();
        self.out.push_str("null");
    }

    /// Writes a quoted, escaped string.
    ///
    /// The escapes are JSON's own (RFC 8259 §7): the quote, the backslash, and the control
    /// characters below `0x20`, which may not appear in a JSON string as they stand. Everything
    /// else - including every non-ASCII character - is written as UTF-8, which is what the
    /// format's encoding is.
    fn quote(&mut self, value: &str) {
        self.out.push('"');
        for character in value.chars() {
            match character {
                '"' => self.out.push_str("\\\""),
                '\\' => self.out.push_str("\\\\"),
                '\n' => self.out.push_str("\\n"),
                '\r' => self.out.push_str("\\r"),
                '\t' => self.out.push_str("\\t"),
                '\u{08}' => self.out.push_str("\\b"),
                '\u{0c}' => self.out.push_str("\\f"),
                control if (control as u32) < 0x20 => {
                    self.out.push_str(&format!("\\u{:04x}", control as u32));
                }
                other => self.out.push(other),
            }
        }
        self.out.push('"');
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::import::{ImportFormat, import};
    use crate::otp::{Algorithm, Digits};
    use crate::vault::{Entry, EntryId, GroupId};

    /// One entry, built the way a scanned code would be.
    fn entry(uri: &str, now: u64) -> Entry {
        let parsed = crate::uri::parse(uri).expect("the uri is valid");
        crate::vault::entry_from_parsed_uri(parsed, now).expect("the entry is valid")
    }

    /// The five schemes, one URI each, in the spellings the reference implementation writes.
    const URIS: [&str; 5] = [
        "otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&period=60",
        "otpauth://hotp/Bank:bob?secret=JBSWY3DPEHPK3PXP&issuer=Bank&counter=7&digits=8",
        "otpauth://steam/alice?secret=JBSWY3DPEHPK3PXP",
        "motp:/Example:alice?secret=deadbeef&issuer=Example&pin=GEZDGNBVGY3Q",
        "otpauth://yaotp/alice?secret=LA2V6KMCGYMWWVEW64RNP3JA3I&pin=GEZDGNBVGY3Q",
    ];

    /// The five schemes, one URI each, with a name a test can find them by.
    ///
    /// The names are set rather than taken from the URIs because two of the URIs end in the same
    /// account label, and a test that looked an entry up by name would find the wrong one.
    fn originals() -> Vec<Entry> {
        URIS.iter()
            .enumerate()
            .map(|(index, uri)| {
                let mut built = entry(uri, 1_600_000_000);
                built.name = format!("entry {index}");
                built
            })
            .collect()
    }

    /// A vault holding every scheme, two named groups and an arrangement.
    fn vault() -> (Vault, Vec<EntryId>) {
        let mut vault = Vault::new();
        let ids: Vec<EntryId> = originals()
            .into_iter()
            .map(|built| vault.insert(built).expect("the vault accepts it"))
            .collect();

        let work = vault.create_group("Work".to_owned()).expect("a valid name");
        let home = vault.create_group("Home".to_owned()).expect("a valid name");
        vault
            .assign_to_group(&ids[0], &work)
            .expect("the entry is there");
        vault
            .assign_to_group(&ids[1], &work)
            .expect("the entry is there");
        vault
            .assign_to_group(&ids[2], &home)
            .expect("the entry is there");
        (vault, ids)
    }

    /// The entry of a report, found by the name the test gave it.
    fn find<'a>(
        report: &'a crate::import::ImportReport,
        name: &str,
    ) -> &'a crate::import::ImportedEntry {
        report
            .entries
            .iter()
            .find(|entry| entry.entry.name == name)
            .unwrap_or_else(|| panic!("the export holds no entry named {name}"))
    }

    /// Reads an export back and returns the entries, newest-first in the file's own order.
    fn read_back(text: &str, password: Option<&[u8]>) -> crate::import::ImportReport {
        import(text.as_bytes(), ImportFormat::Json, 1_700_000_000, password)
            .unwrap_or_else(|error| panic!("the export must read back: {error}"))
    }

    /// The whole point: what comes out of the writer goes back in, field by field.
    #[test]
    fn a_plaintext_export_round_trips_through_the_reader() {
        let (vault, _) = vault();
        let text = write(&vault).expect("the export is written");
        let report = read_back(&text, None);
        assert!(report.problems.is_empty(), "actual {:?}", report.problems);
        assert_eq!(report.entries.len(), URIS.len());

        for original in originals() {
            let name = &original.name;
            let read = &find(&report, name).entry;
            assert_eq!(read.issuer, original.issuer, "{name}");
            assert_eq!(read.algorithm, original.algorithm, "{name}");
            assert_eq!(read.digits, original.digits, "{name}");
            assert_eq!(read.kind, original.kind, "{name}");
            assert_eq!(
                read.secret.to_base32(),
                original.secret.to_base32(),
                "{name}"
            );
            assert!(
                !find(&report, name).favorite,
                "this application has no favourites, so none may be invented"
            );
        }
    }

    /// The order of the file is the order the user sees.
    ///
    /// The top group comes first and the named groups follow in their own order, which is what
    /// [`crate::vault::Vault::groups`] defines and what the interface shows. A writer that walked
    /// the vault's storage order instead would produce a file whose rows are in an order no user
    /// ever chose.
    #[test]
    fn the_export_order_is_the_display_order() {
        let (vault, _) = vault();
        let report = read_back(&write(&vault).expect("the export is written"), None);
        let names: Vec<&str> = report
            .entries
            .iter()
            .map(|entry| entry.entry.name.as_str())
            .collect();
        assert_eq!(
            names,
            vec!["entry 3", "entry 4", "entry 0", "entry 1", "entry 2"],
            "the top group's entries first, then Work, then Home"
        );
    }

    /// The groups and the membership travel, which is the half only this format carries.
    #[test]
    fn the_groups_and_their_order_survive_the_round_trip() {
        let (vault, _) = vault();
        let text = write(&vault).expect("the export is written");
        let report = read_back(&text, None);

        let names: Vec<&str> = report
            .groups
            .iter()
            .map(|group| group.name.as_str())
            .collect();
        assert_eq!(names, vec!["Work", "Home"], "the order is the vault's");
        assert_eq!(find(&report, "entry 0").groups, vec![report.groups[0].id]);
        assert_eq!(find(&report, "entry 1").groups, vec![report.groups[0].id]);
        assert_eq!(find(&report, "entry 2").groups, vec![report.groups[1].id]);
        assert!(
            find(&report, "entry 3").groups.is_empty(),
            "an entry in no named group names none"
        );
        assert!(find(&report, "entry 4").groups.is_empty());
    }

    /// The document carries the fields the format specifies, in the shape it specifies.
    #[test]
    fn the_document_has_the_shape_of_the_format() {
        let (vault, _) = vault();
        let text = write(&vault).expect("the export is written");
        let root: tinyjson::JsonValue = text.parse().expect("it is valid JSON");
        let root = root
            .get::<std::collections::HashMap<String, tinyjson::JsonValue>>()
            .expect("the document is an object");

        assert_eq!(
            root.get("version")
                .and_then(|value| value.get::<f64>())
                .copied(),
            Some(1.0)
        );
        let header = root
            .get("header")
            .and_then(|value| value.get::<std::collections::HashMap<String, tinyjson::JsonValue>>())
            .expect("the header is an object");
        assert!(
            header
                .get("slots")
                .is_some_and(tinyjson::JsonValue::is_null),
            "a plaintext export has no slots"
        );
        assert!(
            header
                .get("params")
                .is_some_and(tinyjson::JsonValue::is_null)
        );

        let db = root
            .get("db")
            .and_then(|value| value.get::<std::collections::HashMap<String, tinyjson::JsonValue>>())
            .expect("a plaintext database is an object");
        assert_eq!(
            db.get("version")
                .and_then(|value| value.get::<f64>())
                .copied(),
            Some(3.0)
        );
        assert_eq!(
            db.get("entries")
                .and_then(|value| value.get::<Vec<tinyjson::JsonValue>>())
                .map(Vec::len),
            Some(URIS.len())
        );
        assert_eq!(
            db.get("icons_optimized")
                .and_then(|value| value.get::<bool>())
                .copied(),
            Some(false)
        );

        let first = db
            .get("entries")
            .and_then(|value| value.get::<Vec<tinyjson::JsonValue>>())
            .and_then(|entries| entries.first())
            .and_then(|value| value.get::<std::collections::HashMap<String, tinyjson::JsonValue>>())
            .expect("an entry is an object");
        let types: Vec<&str> = db
            .get("entries")
            .and_then(|value| value.get::<Vec<tinyjson::JsonValue>>())
            .expect("the entries are an array")
            .iter()
            .filter_map(|value| {
                value
                    .get::<std::collections::HashMap<String, tinyjson::JsonValue>>()?
                    .get("type")?
                    .get::<String>()
                    .map(String::as_str)
            })
            .collect();
        assert_eq!(
            types.len(),
            URIS.len(),
            "every scheme is written: {types:?}"
        );
        for scheme in ["totp", "hotp", "steam", "motp", "yandex"] {
            assert!(types.contains(&scheme), "{scheme} is missing: {types:?}");
        }
        assert!(
            first.get("icon").is_some_and(tinyjson::JsonValue::is_null),
            "the icon field is written, and it is null"
        );
        let uuid = first
            .get("uuid")
            .and_then(|value| value.get::<String>())
            .expect("every entry carries a UUID");
        assert_eq!(
            uuid.len(),
            36,
            "the UUID is written in canonical form: {uuid}"
        );
    }

    /// An encrypted export opens with its password, and only with it.
    #[test]
    fn an_encrypted_export_round_trips_through_the_reader() {
        let (vault, _) = vault();
        let text = write_encrypted(&vault, b"correct horse").expect("the export is written");

        let report = read_back(&text, Some(b"correct horse"));
        assert!(report.problems.is_empty(), "actual {:?}", report.problems);
        assert_eq!(report.entries.len(), URIS.len());
        for original in originals() {
            let name = &original.name;
            let read = &find(&report, name).entry;
            assert_eq!(read.kind, original.kind, "{name}");
            assert_eq!(
                read.secret.to_base32(),
                original.secret.to_base32(),
                "{name}"
            );
        }

        // The database is a base64 ciphertext, so nothing of it may appear in the file.
        assert!(
            !text.contains("JBSWY3DPEHPK3PXP"),
            "the secret must not survive in the file as it stands"
        );
        assert!(text.contains("\"db\":\""), "the database is a string");

        let wrong = import(
            text.as_bytes(),
            ImportFormat::Json,
            0,
            Some(b"correct horsf"),
        );
        assert!(
            matches!(wrong, Err(crate::Error::ImportWrongPassword)),
            "actual {wrong:?}"
        );
    }

    /// The scrypt parameters the writer uses are ones the derivation accepts.
    ///
    /// They are constants of the format, so this can only fail if someone edits them: it is the
    /// test that keeps [`crate::Error::ExportParameterRefused`] unreachable rather than a
    /// runtime check that would have to report a broken build to a user.
    #[test]
    fn the_kdf_parameters_are_valid() {
        let parameters = scrypt::Params::new(KDF_LOG_N, KDF_BLOCK_SIZE, KDF_PARALLELISM)
            .expect("the format's own parameters must be valid");
        assert_eq!(u32::from(parameters.log_n()), 15);
        assert_eq!(parameters.r(), 8);
        assert_eq!(parameters.p(), 1);
        assert_eq!(
            KDF_COST,
            1 << KDF_LOG_N,
            "the cost is written as iterations"
        );
    }

    /// A note holding quotes, backslashes and newlines survives, and produces valid JSON.
    #[test]
    fn a_note_is_escaped_rather_than_written_as_it_stands() {
        let mut vault = Vault::new();
        let mut built = entry(URIS[0], 1_600_000_000);
        built.note = "a \"quoted\" \\ line\nand a tab\there \u{1}".to_owned();
        built.name = "名字".to_owned();
        vault.insert(built).expect("the vault is empty");

        let text = write(&vault).expect("the export is written");
        assert!(
            text.parse::<tinyjson::JsonValue>().is_ok(),
            "the escaping must produce valid JSON: {text}"
        );
        let report = read_back(&text, None);
        assert_eq!(
            report.entries[0].entry.note, "a \"quoted\" \\ line\nand a tab\there \u{1}",
            "the note must come back exactly"
        );
        assert_eq!(report.entries[0].entry.name, "名字");
    }

    /// An HOTP counter above 2^53 is written exactly.
    ///
    /// This is the reason the writer is hand-written: the JSON crate this library reads with
    /// holds numbers as `f64`, and writing this counter through it would round it to the nearest
    /// representable value and silently change every code the entry produces.
    ///
    /// The round trip stops at the text on purpose. **Reading** such a counter back is beyond
    /// what the reader can do - its parser holds numbers as `f64` too - and that is a limit of
    /// this library's reader rather than of the file: the value written is the value the vault
    /// holds, and an implementation that reads integers as integers gets it back unchanged.
    /// Nothing in practice reaches it: an HOTP counter is a 32-bit number in the reference
    /// implementation, and 2^53 presses is a hundred million years at one a second.
    #[test]
    fn a_large_counter_is_written_exactly() {
        let counter = (1_u64 << 53) + 7;
        let mut vault = Vault::new();
        let mut built = entry(URIS[1], 1_600_000_000);
        built.kind = EntryKind::Hotp { counter };
        vault.insert(built).expect("the vault is empty");

        let text = write(&vault).expect("the export is written");
        assert!(
            text.contains(&format!("\"counter\":{counter}")),
            "the counter must appear as it is: {text}"
        );
    }

    /// The scheme decides the algorithm it declares, not the entry's own field.
    #[test]
    fn a_scheme_writes_the_algorithm_it_is_defined_with() {
        let mut vault = Vault::new();
        let mut motp = entry(URIS[3], 1_600_000_000);
        // A field that contradicts the scheme. `Entry` allows it; the code a user sees is the
        // scheme's, so that is what a reader has to be told.
        motp.algorithm = Algorithm::Sha512;
        motp.digits = Digits::EIGHT;
        vault.insert(motp).expect("the vault is empty");

        let text = write(&vault).expect("the export is written");
        assert!(text.contains("\"algo\":\"MD5\""), "mOTP is MD5: {text}");

        let report = read_back(&text, None);
        assert_eq!(report.entries[0].entry.kind, entry(URIS[3], 0).kind);
    }

    /// The password is required, and an empty one is not a password.
    #[test]
    fn an_encrypted_export_refuses_a_missing_or_empty_password() {
        let file = crate::vault::VaultFile::create().expect("OS randomness available");
        let missing =
            crate::export::export(&file, crate::export::ExportFormat::EncryptedJson, None);
        assert!(
            matches!(missing, Err(crate::Error::ExportPasswordRequired)),
            "actual {missing:?}"
        );
        let empty =
            crate::export::export(&file, crate::export::ExportFormat::EncryptedJson, Some(b""));
        assert!(
            matches!(empty, Err(crate::Error::ExportPasswordEmpty)),
            "actual {empty:?}"
        );
    }

    /// An entry's own membership is what the `groups` array holds, and the top group is not one.
    #[test]
    fn an_entry_in_the_top_group_names_no_group() {
        let mut vault = Vault::new();
        vault
            .insert(entry(URIS[2], 1_600_000_000))
            .expect("the vault is empty");
        let text = write(&vault).expect("the export is written");
        assert!(text.contains("\"groups\":[]"), "actual {text}");
        assert!(
            text.contains("\"groups\":[]"),
            "the group list is empty too"
        );
        let read = read_back(&text, None);
        assert!(read.groups.is_empty());
        assert!(read.entries[0].groups.is_empty());

        // `GroupId::TOP` is never written, since the top group is not one a file can name.
        assert!(!text.contains(&uuid_text(GroupId::TOP.as_bytes())));
    }

    /// An icon is written as the three fields the reference format defines, and reads back.
    #[test]
    fn an_icon_round_trips_through_the_export() {
        let icon =
            crate::vault::EntryIcon::new(crate::vault::IconMime::Png, vec![0x89, b'P', b'N', b'G'])
                .expect("small icon");
        let mut vault = Vault::new();
        vault
            .insert(entry(URIS[0], 1_600_000_000).with_icon(Some(icon.clone())))
            .expect("the vault is empty");

        let text = write(&vault).expect("the export is written");
        assert!(
            text.contains("\"icon_mime\":\"image/png\""),
            "the media type is written: {text}"
        );
        assert!(
            text.contains(&format!("\"icon_hash\":\"{}\"", hex(&icon.hash()))),
            "the hash is computed from what is stored: {text}"
        );
        assert!(
            text.contains("\"icon\":\"iVBORw==\""),
            "the bytes are the original file, base64: {text}"
        );

        let report = read_back(&text, None);
        assert_eq!(
            report.entries[0].entry.icon,
            Some(icon),
            "the picture survives the round trip"
        );
        assert_eq!(report.dropped.icons, 0);
    }

    /// An entry without an icon writes `icon: null` and no media type, which is the shape the
    /// reference implementation writes.
    #[test]
    fn an_entry_without_an_icon_writes_null_and_nothing_else() {
        let mut vault = Vault::new();
        vault
            .insert(entry(URIS[0], 1_600_000_000))
            .expect("the vault is empty");
        let text = write(&vault).expect("the export is written");
        assert!(text.contains("\"icon\":null"), "actual {text}");
        assert!(!text.contains("icon_mime"), "actual {text}");
        assert!(!text.contains("icon_hash"), "actual {text}");
    }
}
