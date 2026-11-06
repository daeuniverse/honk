use std::ops::Range;

pub(super) struct Layout {
    pub sd: Range<usize>,
    pub body: usize,
    pub names: Vec<Range<usize>>,
    pub values: Vec<Range<usize>>,
}

const INVALID: &str = "expected a valid RFC 5424 message header";

fn token(bytes: &[u8], position: &mut usize, limit: usize) -> Result<Range<usize>, &'static str> {
    let start = *position;
    let length = bytes
        .get(start..)
        .and_then(|tail| tail.iter().position(|b| *b == b' '))
        .ok_or(INVALID)?;
    let end = start + length;
    if length == 0 || length > limit || !bytes[start..end].iter().all(|b| (33..=126).contains(b)) {
        return Err(INVALID);
    }
    *position = end + 1;
    Ok(start..end)
}

fn name(bytes: &[u8], range: Range<usize>) -> bool {
    !range.is_empty()
        && range.len() <= 32
        && bytes[range]
            .iter()
            .all(|b| (33..=126).contains(b) && !b"=]\"".contains(b))
}

pub(super) fn parse(bytes: &[u8]) -> Result<Layout, &'static str> {
    if bytes.first() != Some(&b'<') {
        return Err(INVALID);
    }
    let end = bytes
        .iter()
        .take(5)
        .position(|b| *b == b'>')
        .ok_or(INVALID)?;
    if !(2..=4).contains(&end) || !bytes[1..end].iter().all(u8::is_ascii_digit) {
        return Err(INVALID);
    }
    if end > 2 && bytes[1] == b'0' {
        return Err(INVALID);
    }
    let pri = bytes[1..end]
        .iter()
        .fold(0u16, |n, b| n * 10 + u16::from(b - b'0'));
    if pri > 191 {
        return Err(INVALID);
    }
    let mut position = end + 1;
    let version = token(bytes, &mut position, 3)?;
    if &bytes[version] != b"1" {
        return Err(INVALID);
    }
    let time = token(bytes, &mut position, 32)?;
    let time = std::str::from_utf8(&bytes[time]).map_err(|_| INVALID)?;
    if time != "-" {
        if time.as_bytes().get(10) != Some(&b'T')
            || time.ends_with('z')
            || chrono::DateTime::parse_from_rfc3339(time).is_err()
        {
            return Err(INVALID);
        }
        if let Some((_, fraction)) = time.split_once('.')
            && fraction.bytes().take_while(u8::is_ascii_digit).count() > 6
        {
            return Err(INVALID);
        }
    }
    for limit in [255, 48, 128, 32] {
        token(bytes, &mut position, limit)?;
    }
    let mut layout = Layout {
        sd: position..position,
        body: 0,
        names: Vec::new(),
        values: Vec::new(),
    };
    if bytes.get(position) == Some(&b'-') {
        position += 1;
    } else {
        let mut ids = std::collections::HashSet::new();
        while bytes.get(position) == Some(&b'[') {
            if position > 8192 {
                return Err(INVALID);
            }
            position += 1;
            let start = position;
            while bytes.get(position).is_some_and(|b| !b" ]".contains(b)) {
                position += 1;
            }
            if !name(bytes, start..position) {
                return Err(INVALID);
            }
            if !ids.insert(&bytes[start..position]) {
                return Err(INVALID);
            }
            layout.names.push(start..position);
            let mut parameters = std::collections::HashSet::new();
            while bytes.get(position) == Some(&b' ') {
                position += 1;
                let start = position;
                while bytes.get(position).is_some_and(|b| *b != b'=') {
                    position += 1;
                    if position > 8192 {
                        return Err(INVALID);
                    }
                }
                if !name(bytes, start..position) {
                    return Err(INVALID);
                }
                if !parameters.insert(&bytes[start..position]) {
                    return Err(INVALID);
                }
                layout.names.push(start..position);
                if bytes.get(position..position + 2) != Some(b"=\"") {
                    return Err(INVALID);
                }
                position += 2;
                let start = position;
                loop {
                    if position > 8192 {
                        return Err(INVALID);
                    }
                    match bytes.get(position) {
                        Some(b'"') => break,
                        Some(b'\\') => {
                            position += 1;
                            if !bytes.get(position).is_some_and(|b| b"\\\"]".contains(b)) {
                                return Err(INVALID);
                            }
                        }
                        Some(b) if !b.is_ascii_control() && *b != b']' => {}
                        _ => return Err(INVALID),
                    }
                    position += 1;
                }
                if std::str::from_utf8(&bytes[start..position]).is_err() {
                    return Err(INVALID);
                }
                layout.values.push(start..position);
                position += 1;
            }
            if bytes.get(position) != Some(&b']') {
                return Err(INVALID);
            }
            position += 1;
        }
        if position == layout.sd.start {
            return Err(INVALID);
        }
    }
    if position > 8192 {
        return Err(INVALID);
    }
    layout.sd.end = position;
    layout.body = match bytes.get(position) {
        Some(b' ') => position + 1,
        None => position,
        _ => return Err(INVALID),
    };
    Ok(layout)
}
