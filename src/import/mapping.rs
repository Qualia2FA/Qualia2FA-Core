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

//! The field mapping shared by the readers.
//!
//! Every reader fills in a [`RawEntry`] and hands it to [`RawEntry::into_entry`], so a rule like
//! "a ten-digit code is refused, and here is why" exists once instead of once per format. The
//! readers differ only in how they find the fields; what the fields mean is decided here.

use crate::import::ImportNote;
use crate::motp::MotpPin;
use crate::otp::{Algorithm, Digits, OtpSecret};
use crate::uri::UriType;
use crate::vault::{Entry, EntryKind, Timestamp};
use crate::yaotp::YandexPin;
use crate::{Error, Result};

/// An algorithm as an export spells it.
///
/// Separate from [`Algorithm`] because MD5 is not one of ours: it is the hash mOTP is built on,
/// and offering it as an [`Algorithm`] would offer it as an HMAC choice for TOTP and HOTP, where
/// it means nothing. Keeping the export's spelling distinct lets the mapping say "MD5 belongs to
/// mOTP and nowhere else" instead of losing the value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RawAlgorithm {
    /// HMAC-SHA-1.
    Sha1,
    /// HMAC-SHA-256.
    Sha256,
    /// HMAC-SHA-512.
    Sha512,
    /// MD5, which only mOTP uses.
    Md5,
}

impl RawAlgorithm {
    /// Parses an export's spelling of an algorithm, case-insensitively.
    pub(crate) fn parse(name: &str) -> Option<Self> {
        if name.eq_ignore_ascii_case("SHA1") {
            Some(Self::Sha1)
        } else if name.eq_ignore_ascii_case("SHA256") {
            Some(Self::Sha256)
        } else if name.eq_ignore_ascii_case("SHA512") {
            Some(Self::Sha512)
        } else if name.eq_ignore_ascii_case("MD5") {
            Some(Self::Md5)
        } else {
            None
        }
    }

    /// The algorithm as this crate models it, or `None` for MD5.
    const fn to_algorithm(self) -> Option<Algorithm> {
        match self {
            Self::Sha1 => Some(Algorithm::Sha1),
            Self::Sha256 => Some(Algorithm::Sha256),
            Self::Sha512 => Some(Algorithm::Sha512),
            Self::Md5 => None,
        }
    }
}

/// How an export spells the scheme of an entry, with the parameters that belong to it.
#[derive(Debug)]
pub(crate) enum RawKind {
    /// TOTP, with an optional time step.
    Totp {
        /// The step the export wrote, if any.
        period: Option<u64>,
    },
    /// HOTP with its counter.
    Hotp {
        /// The counter the export wrote.
        counter: u64,
    },
    /// Steam Guard.
    Steam,
    /// mOTP with its optional PIN.
    Motp {
        /// The step the export wrote, if any.
        period: Option<u64>,
        /// The PIN the export wrote, if any.
        pin: Option<String>,
    },
    /// Yandex OTP with its optional PIN.
    Yandex {
        /// The step the export wrote, if any.
        period: Option<u64>,
        /// The PIN the export wrote, if any.
        pin: Option<String>,
    },
}

impl RawKind {
    /// The URI type whose defaults this scheme shares.
    const fn uri_type(&self) -> UriType {
        match self {
            Self::Totp { .. } => UriType::Totp,
            Self::Hotp { .. } => UriType::Hotp,
            Self::Steam => UriType::Steam,
            Self::Motp { .. } => UriType::Motp,
            Self::Yandex { .. } => UriType::Yandex,
        }
    }
}

/// One entry as an export spells it, before any of it is believed.
#[derive(Debug)]
pub(crate) struct RawEntry {
    /// Display name.
    pub(crate) name: String,
    /// Issuer, already normalized: an empty string arrives as `None`.
    pub(crate) issuer: Option<String>,
    /// Free-form note.
    pub(crate) note: String,
    /// Secret, Base32 as every export writes it.
    pub(crate) secret: String,
    /// Hash algorithm the export named, if any.
    pub(crate) algorithm: Option<RawAlgorithm>,
    /// Digit count the export named, if any (one to ten; ten is refused below).
    pub(crate) digits: Option<u8>,
    /// The scheme and its parameters.
    pub(crate) kind: RawKind,
    /// The icon the export carried, already checked against its format limits.
    ///
    /// `None` means "there was no icon, or the one there was could not be kept". The reader is
    /// what decides which, and what note to report: a bad picture costs the picture, never the
    /// entry.
    pub(crate) icon: Option<crate::vault::EntryIcon>,
}

impl RawEntry {
    /// Validates the fields and builds a model entry.
    ///
    /// # What is refused, and why
    ///
    /// - a **secret** that is not Base32, is empty, or (for Yandex) is neither 16 nor 26 bytes
    ///   with a matching checksum: a wrong secret produces wrong codes forever, and nothing on
    ///   screen would say so;
    /// - a **digit count of ten**: RFC 4226 §5.3 truncates the HMAC to 31 bits, so `10^10`
    ///   exceeds the reachable range - most of the code space can never appear and the rest is not
    ///   uniform. A wider integer type does not help; the truncation is what bounds it;
    /// - an **algorithm that contradicts the scheme**: `MD5` on anything but mOTP, anything but
    ///   `SHA256` on Yandex OTP (its eight-byte window reads past the end of a shorter digest),
    ///   anything but `SHA1` on Steam Guard;
    /// - a **zero time step**, which would divide by zero.
    ///
    /// # An mOTP entry's `algorithm` is unused
    ///
    /// The variant says the code comes from MD5, and this crate does not offer MD5 as an HMAC
    /// choice, so the field carries the scheme default. Consumers must read the code shape from
    /// [`EntryKind`] - exactly as with the digit count of a Yandex or Steam entry.
    ///
    /// # Errors
    ///
    /// The first rule above that the entry breaks. The caller turns it into a problem through
    /// [`safe_reason`], so no value from the export reaches the report.
    pub(crate) fn into_entry(self, now: Timestamp) -> Result<(Entry, Vec<ImportNote>)> {
        let uri_type = self.kind.uri_type();
        let notes = Vec::new();

        let algorithm = self.resolve_algorithm()?;
        let digits = self.resolve_digits(uri_type)?;
        let secret = self.resolve_secret()?;

        let RawEntry {
            name,
            issuer,
            note,
            kind,
            icon,
            ..
        } = self;
        let kind = resolve_kind(kind, uri_type)?;

        let issuer = match (uri_type, issuer) {
            // An entry with no source is indistinguishable from a mis-import, so the scheme that
            // names itself supplies the issuer.
            (UriType::Yandex, None) => Some("Yandex".to_owned()),
            (_, issuer) => issuer,
        };

        let entry = Entry::new(
            name,
            issuer,
            String::new(),
            secret,
            algorithm,
            digits,
            kind,
            note,
            now,
            now,
        )?
        .with_icon(icon);
        Ok((entry, notes))
    }

    /// Resolves the hash algorithm, refusing one that contradicts the scheme.
    fn resolve_algorithm(&self) -> Result<Algorithm> {
        let named = self.algorithm.ok_or(Error::ImportMalformed {
            reason: "an entry names an algorithm this library does not know",
        })?;

        match (&self.kind, named) {
            (RawKind::Motp { .. }, RawAlgorithm::Md5) => Ok(Algorithm::default()),
            (RawKind::Motp { .. }, _) => Err(Error::ImportMalformed {
                reason: "an mOTP entry names an algorithm other than MD5",
            }),
            (RawKind::Yandex { .. }, RawAlgorithm::Sha256) => Ok(Algorithm::Sha256),
            (RawKind::Yandex { .. }, _) => Err(Error::ImportMalformed {
                reason: "Yandex OTP is defined for SHA-256 only",
            }),
            (RawKind::Steam, RawAlgorithm::Sha1) => Ok(Algorithm::Sha1),
            (RawKind::Steam, _) => Err(Error::ImportMalformed {
                reason: "Steam Guard is defined for SHA-1 only",
            }),
            (_, RawAlgorithm::Md5) => Err(Error::ImportMalformed {
                reason: "MD5 is only meaningful for mOTP",
            }),
            (_, other) => Ok(other
                .to_algorithm()
                .expect("every variant but MD5 has an equivalent")),
        }
    }

    /// Resolves the digit count, refusing the one this library cannot produce honestly.
    fn resolve_digits(&self, uri_type: UriType) -> Result<Digits> {
        let Some(count) = self.digits else {
            return Ok(uri_type.default_digits());
        };
        Digits::new(count)
    }

    /// Decodes the secret, applying the scheme's own rules.
    fn resolve_secret(&self) -> Result<OtpSecret> {
        let decoded = OtpSecret::from_base32(&self.secret)?;
        match self.kind {
            RawKind::Yandex { .. } => crate::yaotp::normalize_secret(decoded.expose()),
            _ => Ok(decoded),
        }
    }
}

/// Builds the entry kind, filling in the scheme's defaults.
fn resolve_kind(kind: RawKind, uri_type: UriType) -> Result<EntryKind> {
    let default_period = uri_type.default_period();
    let period_or_default = |period: Option<u64>| -> Result<u64> {
        period.or(default_period).ok_or(Error::ImportMalformed {
            reason: "this scheme has no time step but the export gave none either",
        })
    };

    match kind {
        RawKind::Totp { period } => Ok(EntryKind::Totp {
            period: period_or_default(period)?,
        }),
        RawKind::Hotp { counter } => Ok(EntryKind::Hotp { counter }),
        RawKind::Steam => Ok(EntryKind::Steam),
        RawKind::Motp { period, pin } => Ok(EntryKind::Motp {
            period: period_or_default(period)?,
            pin: pin.filter(|text| !text.is_empty()).map(MotpPin::new),
        }),
        RawKind::Yandex { period, pin } => Ok(EntryKind::Yandex {
            period: period_or_default(period)?,
            pin: pin.filter(|text| !text.is_empty()).map(YandexPin::new),
        }),
    }
}

/// Turns a failure into a phrase that is safe to show and to log.
///
/// **This is the only path from an error into a report**, and it deliberately does not use
/// `Display`: several of this crate's errors quote the value that was wrong, and for a secret
/// that means a character and a position of the key material. A problem list ends up in logs, in
/// screenshots attached to bug reports and in crash dumps, so what goes in is decided here,
/// once.
pub(crate) fn safe_reason(error: &Error) -> String {
    match error {
        Error::SecretEmpty => "the secret is empty".to_owned(),
        Error::SecretTooShort { .. } => "the secret is too short".to_owned(),
        Error::UnsupportedDigits { .. } => {
            "the digit count is not a plain number from 1 to 9".to_owned()
        }
        Error::DigitsZero => "a code must have at least one digit".to_owned(),
        Error::DigitsTooMany { count } => format!(
            "a code cannot have {count} digits: RFC 4226 §5.3 truncates the HMAC to 31 bits, so ten or more digits would be biased (1 to 9 are accepted)"
        ),
        Error::InvalidPeriod => "the time step is zero".to_owned(),
        Error::YandexSecretLength { len } => {
            format!("a Yandex secret is 16 or 26 bytes, this one is {len}")
        }
        Error::YandexSecretChecksum => {
            "the Yandex secret's trailing checksum does not match".to_owned()
        }
        Error::PinRequired { otp_type } => {
            format!("{otp_type} needs a PIN and the export carried none")
        }
        Error::FieldTooLong { field, limit, .. } => {
            format!("the {field} is longer than {limit} bytes")
        }
        Error::ImportMalformed { reason } => (*reason).to_owned(),
        _ => "the entry could not be read".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(kind: RawKind) -> RawEntry {
        RawEntry {
            name: "Example".to_owned(),
            issuer: Some("Example".to_owned()),
            note: String::new(),
            secret: "JBSWY3DPEHPK3PXP".to_owned(),
            algorithm: Some(RawAlgorithm::Sha1),
            digits: None,
            kind,
            icon: None,
        }
    }

    fn build(kind: RawKind) -> Entry {
        raw(kind)
            .into_entry(1_700_000_000)
            .expect("the entry is valid")
            .0
    }

    #[test]
    fn a_totp_entry_takes_the_default_step_when_the_export_gives_none() {
        let entry = build(RawKind::Totp { period: None });
        assert_eq!(entry.kind, EntryKind::Totp { period: 30 });
        assert_eq!(entry.digits, Digits::SIX, "the default digit count");
        assert_eq!(entry.algorithm, Algorithm::Sha1);
        assert!(entry.note.is_empty());
        assert!(
            entry.account.is_empty(),
            "the export format has no account field, and inventing one would show up in the interface"
        );
    }

    #[test]
    fn each_scheme_defaults_to_its_own_code_shape() {
        let mut motp = raw(RawKind::Motp {
            period: None,
            pin: None,
        });
        motp.algorithm = Some(RawAlgorithm::Md5);
        assert_eq!(
            motp.into_entry(0).expect("the entry is valid").0.kind,
            EntryKind::Motp {
                period: 10,
                pin: None
            }
        );

        let mut yandex = raw(RawKind::Yandex {
            period: None,
            pin: Some("1234".to_owned()),
        });
        yandex.algorithm = Some(RawAlgorithm::Sha256);
        yandex.issuer = None;
        yandex.secret = "LA2V6KMCGYMWWVEW64RNP3JA3I".to_owned();
        let (entry, notes) = yandex.into_entry(0).expect("the entry is valid");
        assert_eq!(
            entry.kind,
            EntryKind::Yandex {
                period: 30,
                pin: Some(YandexPin::new("1234".to_owned()))
            }
        );
        assert_eq!(entry.digits, Digits::EIGHT, "eight characters");
        assert_eq!(entry.algorithm, Algorithm::Sha256);
        assert_eq!(
            entry.issuer.as_deref(),
            Some("Yandex"),
            "an entry with no source looks like a mis-import"
        );
        assert!(notes.is_empty());
    }

    #[test]
    fn steam_guard_takes_five_characters_and_sha1() {
        let mut steam = raw(RawKind::Steam);
        steam.digits = Some(5);
        let entry = steam.into_entry(0).expect("the entry is valid").0;
        assert_eq!(entry.kind, EntryKind::Steam);
        assert_eq!(entry.digits, Digits::FIVE);
        assert_eq!(entry.algorithm, Algorithm::Sha1);

        let mut wrong_algorithm = raw(RawKind::Steam);
        wrong_algorithm.algorithm = Some(RawAlgorithm::Sha256);
        assert!(wrong_algorithm.into_entry(0).is_err());
    }

    #[test]
    fn ten_digits_is_refused_with_the_reason_attached() {
        let mut entry = raw(RawKind::Totp { period: None });
        entry.digits = Some(10);
        let error = entry.into_entry(0).expect_err("ten digits is refused");
        assert!(
            matches!(error, Error::DigitsTooMany { count: 10 }),
            "actual {error:?}"
        );

        let reason = safe_reason(&error);
        assert!(
            reason.contains("31 bits"),
            "the reason must say why, not only that it is unsupported: {reason}"
        );
    }

    #[test]
    fn md5_is_only_meaningful_for_motp() {
        let mut totp = raw(RawKind::Totp { period: None });
        totp.algorithm = Some(RawAlgorithm::Md5);
        assert!(totp.into_entry(0).is_err());

        let mut motp = raw(RawKind::Motp {
            period: None,
            pin: None,
        });
        motp.algorithm = Some(RawAlgorithm::Md5);
        assert!(motp.into_entry(0).is_ok());

        let mut motp_with_sha = raw(RawKind::Motp {
            period: None,
            pin: None,
        });
        motp_with_sha.algorithm = Some(RawAlgorithm::Sha256);
        assert!(motp_with_sha.into_entry(0).is_err());
    }

    #[test]
    fn yandex_refuses_a_digest_shorter_than_its_window() {
        for algorithm in [RawAlgorithm::Sha1, RawAlgorithm::Sha512, RawAlgorithm::Md5] {
            let mut yandex = raw(RawKind::Yandex {
                period: None,
                pin: None,
            });
            yandex.algorithm = Some(algorithm);
            yandex.secret = "LA2V6KMCGYMWWVEW64RNP3JA3I".to_owned();
            assert!(
                yandex.into_entry(0).is_err(),
                "{algorithm:?} must be refused for Yandex OTP"
            );
        }
    }

    /// An icon the reader kept is attached to the entry, and produces no note of its own.
    #[test]
    fn a_kept_icon_reaches_the_entry() {
        let icon = crate::vault::EntryIcon::new(crate::vault::IconMime::Png, vec![1, 2, 3])
            .expect("small icon");
        let mut with_icon = raw(RawKind::Totp { period: None });
        with_icon.icon = Some(icon.clone());
        let (entry, notes) = with_icon.into_entry(0).expect("the entry is still valid");
        assert_eq!(entry.icon, Some(icon));
        assert!(
            notes.is_empty(),
            "keeping the icon is not something to report"
        );
    }

    #[test]
    fn a_bad_secret_is_reported_without_quoting_it() {
        let mut entry = raw(RawKind::Totp { period: None });
        entry.secret = "NOT-BASE32-AT-ALL".to_owned();
        let error = entry.into_entry(0).expect_err("the secret is not Base32");
        let reason = safe_reason(&error);
        assert!(
            !reason.contains("NOT-BASE32") && !reason.contains("NOT"),
            "the reason must not quote the secret: {reason}"
        );
        assert!(!reason.is_empty());
    }

    #[test]
    fn a_zero_step_is_refused() {
        let error = raw(RawKind::Totp { period: Some(0) })
            .into_entry(0)
            .expect_err("a step of zero would divide by zero");
        assert!(matches!(error, Error::InvalidPeriod), "actual {error:?}");
    }
}
