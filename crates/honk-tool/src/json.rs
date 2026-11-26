//! Minimal RFC 8259 JSON writer and pipe-safe stdout helper for `honk-tool`.

use std::fmt::Write as _;

pub struct JsonBuf(String);

impl JsonBuf {
    pub fn new() -> Self {
        Self(String::new())
    }

    pub fn finish(mut self) -> String {
        self.0.push('\n');
        self.0
    }

    pub fn raw(&mut self, s: &str) {
        self.0.push_str(s);
    }

    pub fn null(&mut self) {
        self.0.push_str("null");
    }

    pub fn bool(&mut self, v: bool) {
        self.0.push_str(if v { "true" } else { "false" });
    }

    pub fn uint(&mut self, v: impl Into<u64>) {
        let _ = write!(self.0, "{}", v.into());
    }

    pub fn usize(&mut self, v: usize) {
        let _ = write!(self.0, "{v}");
    }

    pub fn str(&mut self, s: &str) {
        self.0.push('"');
        for ch in s.chars() {
            match ch {
                '"' => self.0.push_str("\\\""),
                '\\' => self.0.push_str("\\\\"),
                '\x08' => self.0.push_str("\\b"),
                '\x0c' => self.0.push_str("\\f"),
                '\n' => self.0.push_str("\\n"),
                '\r' => self.0.push_str("\\r"),
                '\t' => self.0.push_str("\\t"),
                c if (c as u32) < 0x20 => {
                    let _ = write!(self.0, "\\u{:04x}", c as u32);
                }
                c => self.0.push(c),
            }
        }
        self.0.push('"');
    }

    pub fn opt_str(&mut self, v: Option<&str>) {
        match v {
            Some(s) => self.str(s),
            None => self.null(),
        }
    }

    pub fn opt_bool(&mut self, v: Option<bool>) {
        match v {
            Some(b) => self.bool(b),
            None => self.null(),
        }
    }

    pub fn opt_u32(&mut self, v: Option<u32>) {
        match v {
            Some(n) => self.uint(n),
            None => self.null(),
        }
    }

    pub fn opt_usize(&mut self, v: Option<usize>) {
        match v {
            Some(n) => self.usize(n),
            None => self.null(),
        }
    }

    pub fn str_slice(&mut self, items: &[&str]) {
        self.0.push('[');
        for (i, item) in items.iter().enumerate() {
            if i > 0 {
                self.0.push(',');
            }
            self.str(item);
        }
        self.0.push(']');
    }

    pub fn key(&mut self, first: &mut bool, name: &str) {
        if !*first {
            self.0.push(',');
        }
        *first = false;
        self.str(name);
        self.0.push(':');
    }
}

/// Ignore `BrokenPipe` so piping into `head`, `grep`, or `jq` exits cleanly.
pub fn write_stdout(out: &str) -> anyhow::Result<()> {
    use std::io::Write as _;
    let mut stdout = std::io::stdout().lock();
    match stdout.write_all(out.as_bytes()) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::JsonBuf;

    #[test]
    fn escapes_rfc8259_special_and_control_characters() {
        let mut buf = JsonBuf::new();
        buf.str("a\"b\\c\x08\x0c\n\r\t\x00\x1fΩ");
        assert_eq!(
            buf.finish(),
            "\"a\\\"b\\\\c\\b\\f\\n\\r\\t\\u0000\\u001fΩ\"\n"
        );
    }
}
