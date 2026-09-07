//! Quote-aware fields for named and Quantumult X records.

#[derive(Clone, Debug)]
pub(super) struct Field {
    pub(super) value: String,
    /// The field began with a quote, so `=` belongs to a positional payload.
    pub(super) quoted: bool,
    /// A quoted value after `=` may intentionally contain edge spaces.
    pub(super) quoted_value: bool,
    /// The first `=` outside quotes, used to split the record header without
    /// confusing an escaped/quoted `=` in a display name for the delimiter.
    pub(super) unquoted_equals: Option<usize>,
}

/// Split on unquoted commas; backslash escapes the following character.
pub(super) fn split_fields(line: &str) -> Option<Vec<Field>> {
    let mut fields = Vec::new();
    let mut field = String::new();
    let mut quote = None::<char>;
    let mut escaped = false;
    let mut started = false;
    let mut after_quote = false;
    let mut quoted = false;
    let mut quoted_value = false;
    let mut unquoted_equals = None::<usize>;

    for ch in line.chars() {
        if escaped {
            field.push(ch);
            started = true;
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if let Some(open) = quote {
            if ch == open {
                quote = None;
                after_quote = true;
            } else {
                field.push(ch);
            }
            continue;
        }
        if after_quote && ch.is_whitespace() {
            continue;
        }
        after_quote = false;
        match ch {
            '\'' | '"' => {
                if !started {
                    quoted = true;
                } else if field.contains('=') {
                    quoted_value = true;
                    field.truncate(field.trim_end().len());
                }
                quote = Some(ch);
                started = true;
            }
            ',' => {
                fields.push(Field {
                    value: if quoted || quoted_value {
                        std::mem::take(&mut field)
                    } else {
                        field.trim().to_string()
                    },
                    quoted,
                    quoted_value,
                    unquoted_equals,
                });
                field.clear();
                started = false;
                after_quote = false;
                quoted = false;
                quoted_value = false;
                unquoted_equals = None;
            }
            _ => {
                if started || !ch.is_whitespace() {
                    field.push(ch);
                }
                if !ch.is_whitespace() {
                    started = true;
                }
                if ch == '=' && unquoted_equals.is_none() {
                    unquoted_equals = Some(field.len() - ch.len_utf8());
                }
            }
        }
    }
    if escaped {
        field.push('\\');
    }
    if quote.is_some() {
        return None;
    }
    fields.push(Field {
        value: if quoted || quoted_value {
            field
        } else {
            field.trim().to_string()
        },
        quoted,
        quoted_value,
        unquoted_equals,
    });
    Some(fields)
}
