//! Minimal JSONC support: strips `//` and `/* */` comments, trailing commas and a BOM.
//! String-aware, linear time and iterative, so hostile input cannot overflow the stack.

/// Turn JSONC text into plain JSON text.
pub fn strip(input: &str) -> String {
    let input = input.strip_prefix('\u{feff}').unwrap_or(input);
    let no_comments = strip_comments(input.as_bytes());
    let clean = strip_trailing_commas(&no_comments);
    String::from_utf8_lossy(&clean).into_owned()
}

fn strip_comments(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(b.len());
    let (mut i, mut in_str, mut escaped) = (0, false, false);
    while i < b.len() {
        let c = b[i];
        if in_str {
            out.push(c);
            if escaped {
                escaped = false;
            } else if c == b'\\' {
                escaped = true;
            } else if c == b'"' {
                in_str = false;
            }
            i += 1;
        } else if c == b'"' {
            in_str = true;
            out.push(c);
            i += 1;
        } else if c == b'/' && b.get(i + 1) == Some(&b'/') {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
        } else if c == b'/' && b.get(i + 1) == Some(&b'*') {
            i += 2;
            while i < b.len() && !(b[i] == b'*' && b.get(i + 1) == Some(&b'/')) {
                i += 1;
            }
            i = (i + 2).min(b.len());
            out.push(b' ');
        } else {
            out.push(c);
            i += 1;
        }
    }
    out
}

fn strip_trailing_commas(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(b.len());
    let (mut in_str, mut escaped) = (false, false);
    for (i, &c) in b.iter().enumerate() {
        if in_str {
            if escaped {
                escaped = false;
            } else if c == b'\\' {
                escaped = true;
            } else if c == b'"' {
                in_str = false;
            }
        } else if c == b'"' {
            in_str = true;
        } else if c == b',' {
            let next = b[i + 1..].iter().find(|x| !x.is_ascii_whitespace());
            if matches!(next, Some(b'}' | b']')) {
                continue;
            }
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::strip;

    #[test]
    fn strips_comments_and_trailing_commas_but_not_inside_strings() {
        let src =
            "\u{feff}{\n// line\n\"a\": \"http://x/*y*/, ]\", /* block */\n\"b\": [1, 2,],\n}\n";
        let v: serde_json::Value = serde_json::from_str(&strip(src)).unwrap();
        assert_eq!(v["a"], "http://x/*y*/, ]");
        assert_eq!(v["b"], serde_json::json!([1, 2]));
    }

    #[test]
    fn unterminated_comment_and_escaped_quote_do_not_panic() {
        assert_eq!(
            strip("{\"a\": \"q\\\"//\"} /* open"),
            "{\"a\": \"q\\\"//\"}  "
        );
        assert_eq!(strip("//"), "");
    }
}
