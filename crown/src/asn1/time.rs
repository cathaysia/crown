//! UTCTime / GeneralizedTime parsing and encoding.
//!
//! Times are represented as calendar fields plus a flag choosing the wire
//! form. Comparisons and validity checks go through [`Asn1Time::to_unix`],
//! which is a pure calendar computation and therefore works without `std`.

use crate::error::{CryptoError, CryptoResult};

/// The number of seconds between 1970-01-01 and 2000-03-01 in the civil
/// calendar algorithm (Howard Hinnant's `days_from_civil` epoch offset).
const CIVIL_EPOCH_OFFSET: i64 = 719_468;

/// An ASN.1 calendar time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Asn1Time {
    /// Calendar year (e.g. 2026).
    pub year: i32,
    /// Month, 1..=12.
    pub month: u8,
    /// Day of month, 1..=31.
    pub day: u8,
    /// Hour, 0..=23.
    pub hour: u8,
    /// Minute, 0..=59.
    pub minute: u8,
    /// Second, 0..=59.
    pub second: u8,
    /// Encode as UTCTime when true, GeneralizedTime otherwise.
    pub utc: bool,
}

impl Asn1Time {
    /// Build a time, validating the field ranges.
    pub fn new(
        year: i32,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
        utc: bool,
    ) -> CryptoResult<Self> {
        let time = Asn1Time {
            year,
            month,
            day,
            hour,
            minute,
            second,
            utc,
        };
        time.validate()?;
        Ok(time)
    }

    /// Parse a UTCTime (`YYMMDDHHMM[SS]Z`).
    pub fn parse_utc(content: &[u8]) -> CryptoResult<Self> {
        let digits = parse_digits(content, 2)?;
        let year = if digits[0] >= 50 {
            1900 + digits[0] as i32
        } else {
            2000 + digits[0] as i32
        };
        let time = Asn1Time {
            year,
            month: digits[1] as u8,
            day: digits[2] as u8,
            hour: digits[3] as u8,
            minute: digits[4] as u8,
            second: digits.get(5).copied().unwrap_or(0) as u8,
            utc: true,
        };
        time.validate()?;
        Ok(time)
    }

    /// Parse a GeneralizedTime (`YYYYMMDDHHMM[SS][.fff]Z`).
    pub fn parse_generalized(content: &[u8]) -> CryptoResult<Self> {
        let digits = parse_digits(content, 4)?;
        let time = Asn1Time {
            year: digits[0] as i32,
            month: digits[1] as u8,
            day: digits[2] as u8,
            hour: digits[3] as u8,
            minute: digits[4] as u8,
            second: digits.get(5).copied().unwrap_or(0) as u8,
            utc: false,
        };
        time.validate()?;
        Ok(time)
    }

    /// Seconds since the Unix epoch (UTC, ignoring leap seconds).
    pub fn to_unix(self) -> i64 {
        days_from_civil(self.year, self.month, self.day) * 86_400
            + self.hour as i64 * 3600
            + self.minute as i64 * 60
            + self.second as i64
    }

    /// Build a time from seconds since the Unix epoch.
    pub fn from_unix(timestamp: i64, utc: bool) -> Self {
        let days = timestamp.div_euclid(86_400);
        let secs = timestamp.rem_euclid(86_400);
        let (year, month, day) = civil_from_days(days);
        Asn1Time {
            year,
            month,
            day,
            hour: (secs / 3600) as u8,
            minute: ((secs % 3600) / 60) as u8,
            second: (secs % 60) as u8,
            utc,
        }
    }

    /// Encode as UTCTime content (without tag and length).
    pub fn encode_utc(&self) -> alloc::vec::Vec<u8> {
        let year = self.year.rem_euclid(100);
        alloc::format!(
            "{:02}{:02}{:02}{:02}{:02}{:02}Z",
            year,
            self.month,
            self.day,
            self.hour,
            self.minute,
            self.second
        )
        .into_bytes()
    }

    /// Encode as GeneralizedTime content (without tag and length).
    pub fn encode_generalized(&self) -> alloc::vec::Vec<u8> {
        alloc::format!(
            "{:04}{:02}{:02}{:02}{:02}{:02}Z",
            self.year,
            self.month,
            self.day,
            self.hour,
            self.minute,
            self.second
        )
        .into_bytes()
    }

    /// Encode using the wire form this value was parsed from, choosing
    /// UTCTime only when the year fits its 1950..=2049 range.
    pub fn encode(&self) -> alloc::vec::Vec<u8> {
        if self.utc && (1950..=2049).contains(&self.year) {
            self.encode_utc()
        } else {
            self.encode_generalized()
        }
    }

    fn validate(&self) -> CryptoResult<()> {
        if !(1..=12).contains(&self.month) {
            return Err(CryptoError::StrError("asn1: invalid time month"));
        }
        if self.day < 1 || self.day > days_in_month(self.year, self.month) {
            return Err(CryptoError::StrError("asn1: invalid time day"));
        }
        if self.hour > 23 || self.minute > 59 || self.second > 59 {
            return Err(CryptoError::StrError("asn1: invalid time"));
        }
        Ok(())
    }
}

impl PartialOrd for Asn1Time {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Asn1Time {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.to_unix().cmp(&other.to_unix())
    }
}

/// Decode `content` as `[digits; n]` (plus optional seconds/fraction) with a
/// trailing `Z`, as required by RFC 5280.
fn parse_digits(content: &[u8], year_digits: usize) -> CryptoResult<alloc::vec::Vec<i64>> {
    if content.last() != Some(&b'Z') {
        return Err(CryptoError::StrError("asn1: invalid time"));
    }
    let body = &content[..content.len() - 1];
    // Drop an optional fraction of a second; DER forbids it, but some
    // encoders emit it and the value is unambiguous.
    let body = match body.iter().position(|&b| b == b'.') {
        Some(pos) => {
            if !body[pos + 1..].iter().all(u8::is_ascii_digit) || pos + 1 == body.len() {
                return Err(CryptoError::StrError("asn1: invalid time"));
            }
            &body[..pos]
        }
        None => body,
    };
    let min_len = year_digits + 8;
    if body.len() < min_len || body.len() > min_len + 2 || !(body.len() - min_len).is_multiple_of(2)
    {
        return Err(CryptoError::StrError("asn1: invalid time length"));
    }
    let mut values = alloc::vec::Vec::new();
    for chunk in body.chunks(2) {
        if !chunk.iter().all(u8::is_ascii_digit) {
            return Err(CryptoError::StrError("asn1: invalid time digit"));
        }
        values.push(((chunk[0] - b'0') as i64) * 10 + (chunk[1] - b'0') as i64);
    }
    if year_digits == 4 {
        // The year occupies the first two digit pairs.
        values[0] = values[0] * 100 + values[1];
        values.remove(1);
    }
    Ok(values)
}

fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn days_in_month(year: i32, month: u8) -> u8 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

/// Days since 1970-01-01 for a proleptic Gregorian date (Hinnant's
/// `days_from_civil`).
fn days_from_civil(year: i32, month: u8, day: u8) -> i64 {
    let year = year as i64;
    let month = month as i64;
    let day = day as i64;
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let day_of_year = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - CIVIL_EPOCH_OFFSET
}

/// Inverse of [`days_from_civil`].
fn civil_from_days(days: i64) -> (i32, u8, u8) {
    let days = days + CIVIL_EPOCH_OFFSET;
    let era = days.div_euclid(146_097);
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    };
    let year = if month <= 2 { year + 1 } else { year };
    (year as i32, month as u8, day as u8)
}
