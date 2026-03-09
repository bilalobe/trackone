#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Timestamp {
    pub unix_seconds: i64,
}

pub fn parse_rfc3339_timestamp(value: &str) -> Result<Timestamp, ()> {
    let bytes = value.as_bytes();
    if bytes.len() < 20 {
        return Err(());
    }

    let year = parse_u32(bytes, 0, 4)? as i32;
    expect(bytes, 4, b'-')?;
    let month = parse_u32(bytes, 5, 2)?;
    expect(bytes, 7, b'-')?;
    let day = parse_u32(bytes, 8, 2)?;
    expect(bytes, 10, b'T')?;
    let hour = parse_u32(bytes, 11, 2)?;
    expect(bytes, 13, b':')?;
    let minute = parse_u32(bytes, 14, 2)?;
    expect(bytes, 16, b':')?;
    let second = parse_u32(bytes, 17, 2)?;

    let mut pos = 19;
    if pos < bytes.len() && bytes[pos] == b'.' {
        pos += 1;
        let frac_start = pos;
        while pos < bytes.len() && bytes[pos].is_ascii_digit() {
            pos += 1;
        }
        if pos == frac_start {
            return Err(());
        }
    }

    let offset_seconds = match bytes.get(pos).copied() {
        Some(b'Z') => {
            pos += 1;
            0
        }
        Some(b'+') | Some(b'-') => {
            let sign = if bytes[pos] == b'+' { 1 } else { -1 };
            pos += 1;
            let offset_hour = parse_u32(bytes, pos, 2)? as i32;
            pos += 2;
            expect(bytes, pos, b':')?;
            pos += 1;
            let offset_minute = parse_u32(bytes, pos, 2)? as i32;
            pos += 2;
            if offset_hour > 23 || offset_minute > 59 {
                return Err(());
            }
            sign * (offset_hour * 3600 + offset_minute * 60)
        }
        _ => return Err(()),
    };

    if pos != bytes.len() {
        return Err(());
    }

    validate_date_time(year, month, day, hour, minute, second)?;
    let days = days_from_civil(year, month, day);
    let local_seconds =
        days * 86_400 + i64::from(hour) * 3600 + i64::from(minute) * 60 + i64::from(second);

    Ok(Timestamp {
        unix_seconds: local_seconds - i64::from(offset_seconds),
    })
}

pub fn format_rfc3339_utc(unix_seconds: i64) -> Result<String, ()> {
    let days = unix_seconds.div_euclid(86_400);
    let seconds_of_day = unix_seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = seconds_of_day / 3600;
    let minute = (seconds_of_day % 3600) / 60;
    let second = seconds_of_day % 60;

    Ok(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z"
    ))
}

fn parse_u32(bytes: &[u8], start: usize, len: usize) -> Result<u32, ()> {
    let slice = bytes.get(start..start + len).ok_or(())?;
    let mut value = 0u32;
    for byte in slice {
        if !byte.is_ascii_digit() {
            return Err(());
        }
        value = value * 10 + u32::from(byte - b'0');
    }
    Ok(value)
}

fn expect(bytes: &[u8], idx: usize, expected: u8) -> Result<(), ()> {
    match bytes.get(idx) {
        Some(actual) if *actual == expected => Ok(()),
        _ => Err(()),
    }
}

fn validate_date_time(
    year: i32,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
) -> Result<(), ()> {
    if !(1..=12).contains(&month) {
        return Err(());
    }
    let max_day = days_in_month(year, month);
    if day == 0 || day > max_day {
        return Err(());
    }
    if hour > 23 || minute > 59 || second > 59 {
        return Err(());
    }
    Ok(())
}

fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn days_in_month(year: i32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

fn days_from_civil(year: i32, month: u32, day: u32) -> i64 {
    let mut year = i64::from(year);
    let month = i64::from(month);
    let day = i64::from(day);
    year -= if month <= 2 { 1 } else { 0 };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let yoe = year - era * 400;
    let doy = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(days: i64) -> (i32, u32, u32) {
    let days = days + 719_468;
    let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
    let doe = days - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    let year = y + if month <= 2 { 1 } else { 0 };
    (year as i32, month as u32, day as u32)
}

#[cfg(test)]
mod tests {
    use super::{format_rfc3339_utc, parse_rfc3339_timestamp, Timestamp};

    #[test]
    fn parses_zulu_time() {
        assert_eq!(
            parse_rfc3339_timestamp("2026-03-06T00:05:01Z"),
            Ok(Timestamp {
                unix_seconds: 1_772_755_501
            })
        );
    }

    #[test]
    fn parses_offset_time() {
        assert_eq!(
            parse_rfc3339_timestamp("2026-03-06T01:05:01+01:00"),
            Ok(Timestamp {
                unix_seconds: 1_772_755_501
            })
        );
    }

    #[test]
    fn formats_unix_time() {
        assert_eq!(
            format_rfc3339_utc(1_772_755_501).expect("format should succeed"),
            "2026-03-06T00:05:01Z"
        );
    }
}
