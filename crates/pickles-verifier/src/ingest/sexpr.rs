//! Minimal OCaml `sexp_of_t` text parser.
//!
//! Only what we need to decode `Pickles.Proof.Proofs_verified_2.Repr.Stable.V2`
//! as produced by `Pickles.proofToBase64` (o1js v2.15). The format is OCaml
//! `ppx_sexp_conv`:
//!
//!   * Lists are `(a b c)`, atoms are bare tokens or `"quoted"` strings.
//!   * Records are lists of `(field value)` pairs.
//!   * Sum types render as `(Tag value)` (non-nullary) or bare `Tag`.
//!   * Optionals are `()` for None or `(value)` for Some.
//!
//! Quoted-atom escapes we support: `\\`, `\"`, `\n`, `\t`, `\r`, and `\NNN`
//! (three-digit decimal). The fixture's only escape in practice is `"\t"` for
//! `domain_log2` (OCaml byte 9), but we cover the common set.
//!
//! Errors carry a byte offset so the parser is debuggable against the raw text.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sexp {
    Atom(String),
    List(Vec<Sexp>),
}

#[derive(Debug)]
pub struct ParseError {
    pub offset: usize,
    pub message: String,
}

impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "sexp parse error at offset {}: {}", self.offset, self.message)
    }
}

impl std::error::Error for ParseError {}

pub fn parse(input: &str) -> Result<Sexp, ParseError> {
    let bytes = input.as_bytes();
    let mut pos = 0;
    skip_ws(bytes, &mut pos);
    let s = parse_one(bytes, &mut pos)?;
    skip_ws(bytes, &mut pos);
    if pos != bytes.len() {
        return Err(err(pos, format!("trailing bytes (first: {:?})", bytes[pos] as char)));
    }
    Ok(s)
}

fn err(offset: usize, message: String) -> ParseError {
    ParseError { offset, message }
}

fn skip_ws(bytes: &[u8], pos: &mut usize) {
    while *pos < bytes.len() {
        match bytes[*pos] {
            b' ' | b'\t' | b'\n' | b'\r' => *pos += 1,
            _ => break,
        }
    }
}

fn parse_one(bytes: &[u8], pos: &mut usize) -> Result<Sexp, ParseError> {
    if *pos >= bytes.len() {
        return Err(err(*pos, "unexpected EOF".to_string()));
    }
    match bytes[*pos] {
        b'(' => parse_list(bytes, pos),
        b')' => Err(err(*pos, "unexpected ')'".to_string())),
        b'"' => parse_quoted(bytes, pos).map(Sexp::Atom),
        _ => parse_bare(bytes, pos).map(Sexp::Atom),
    }
}

fn parse_list(bytes: &[u8], pos: &mut usize) -> Result<Sexp, ParseError> {
    debug_assert_eq!(bytes[*pos], b'(');
    *pos += 1;
    let mut items = Vec::new();
    loop {
        skip_ws(bytes, pos);
        if *pos >= bytes.len() {
            return Err(err(*pos, "unclosed list".to_string()));
        }
        if bytes[*pos] == b')' {
            *pos += 1;
            return Ok(Sexp::List(items));
        }
        items.push(parse_one(bytes, pos)?);
    }
}

fn parse_quoted(bytes: &[u8], pos: &mut usize) -> Result<String, ParseError> {
    debug_assert_eq!(bytes[*pos], b'"');
    *pos += 1;
    let mut out = Vec::<u8>::new();
    while *pos < bytes.len() {
        let c = bytes[*pos];
        if c == b'"' {
            *pos += 1;
            return String::from_utf8(out)
                .map_err(|e| err(*pos, format!("quoted atom not UTF-8: {e}")));
        }
        if c == b'\\' {
            *pos += 1;
            if *pos >= bytes.len() {
                return Err(err(*pos, "trailing backslash in quoted atom".to_string()));
            }
            let esc = bytes[*pos];
            match esc {
                b'\\' => out.push(b'\\'),
                b'"' => out.push(b'"'),
                b'n' => out.push(b'\n'),
                b't' => out.push(b'\t'),
                b'r' => out.push(b'\r'),
                b'b' => out.push(0x08),
                b'0'..=b'9' => {
                    // \NNN three-digit decimal byte
                    if *pos + 2 >= bytes.len() {
                        return Err(err(*pos, "truncated \\NNN escape".to_string()));
                    }
                    let s = core::str::from_utf8(&bytes[*pos..*pos + 3])
                        .map_err(|e| err(*pos, format!("\\NNN: {e}")))?;
                    let n: u32 = s
                        .parse()
                        .map_err(|e| err(*pos, format!("\\NNN parse: {e}")))?;
                    if n > 255 {
                        return Err(err(*pos, format!("\\NNN out of range: {n}")));
                    }
                    out.push(n as u8);
                    *pos += 2;
                }
                other => return Err(err(*pos, format!("unknown escape \\{:?}", other as char))),
            }
            *pos += 1;
        } else {
            out.push(c);
            *pos += 1;
        }
    }
    Err(err(*pos, "unterminated quoted atom".to_string()))
}

fn parse_bare(bytes: &[u8], pos: &mut usize) -> Result<String, ParseError> {
    let start = *pos;
    while *pos < bytes.len() {
        match bytes[*pos] {
            b' ' | b'\t' | b'\n' | b'\r' | b'(' | b')' | b'"' => break,
            _ => *pos += 1,
        }
    }
    if *pos == start {
        return Err(err(*pos, "empty atom".to_string()));
    }
    core::str::from_utf8(&bytes[start..*pos])
        .map(|s| s.to_string())
        .map_err(|e| err(*pos, format!("bare atom not UTF-8: {e}")))
}

// ---------------------------------------------------------------------------
// Navigator helpers
// ---------------------------------------------------------------------------

impl Sexp {
    pub fn as_atom(&self) -> Result<&str, String> {
        match self {
            Sexp::Atom(s) => Ok(s.as_str()),
            Sexp::List(_) => Err("expected atom, got list".to_string()),
        }
    }

    pub fn as_list(&self) -> Result<&[Sexp], String> {
        match self {
            Sexp::List(items) => Ok(items.as_slice()),
            Sexp::Atom(a) => Err(format!("expected list, got atom {a:?}")),
        }
    }

    /// Treat this sexp as a record `((k1 v1)(k2 v2)…)` and find the value for
    /// `name`. Each pair is a 2-element list `(key, value)`.
    pub fn field(&self, name: &str) -> Result<&Sexp, String> {
        let items = self.as_list().map_err(|e| format!("field `{name}`: {e}"))?;
        for entry in items {
            let pair = entry.as_list().map_err(|e| format!("field `{name}`: {e}"))?;
            if pair.len() < 1 {
                continue;
            }
            if let Ok(k) = pair[0].as_atom() {
                if k == name {
                    if pair.len() == 1 {
                        // `(name)` with no value: treat as the empty list (None for option).
                        return Err(format!("field `{name}`: value missing"));
                    }
                    // OCaml `ppx_sexp_conv` records use `(k v)` (length 2). If
                    // there are more, return the tail as an implicit list.
                    if pair.len() == 2 {
                        return Ok(&pair[1]);
                    }
                    // Unusual: keep this branch returning an error since the
                    // proof tree we're decoding always uses (k v) pairs.
                    return Err(format!(
                        "field `{name}`: expected (key value), got {} elements",
                        pair.len()
                    ));
                }
            }
        }
        Err(format!("field `{name}` not found"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_atom() {
        assert_eq!(parse("foo").unwrap(), Sexp::Atom("foo".into()));
    }

    #[test]
    fn parses_list() {
        let s = parse("(a b c)").unwrap();
        let items = s.as_list().unwrap();
        assert_eq!(items.len(), 3);
        assert_eq!(items[0].as_atom().unwrap(), "a");
    }

    #[test]
    fn parses_record_field_lookup() {
        let s = parse("((alpha (1 2)) (beta (3 4)))").unwrap();
        let beta = s.field("beta").unwrap();
        let limbs = beta.as_list().unwrap();
        assert_eq!(limbs[0].as_atom().unwrap(), "3");
        assert_eq!(limbs[1].as_atom().unwrap(), "4");
    }

    #[test]
    fn parses_quoted_with_tab_escape() {
        let s = parse("(\"\\t\")").unwrap();
        let items = s.as_list().unwrap();
        assert_eq!(items[0].as_atom().unwrap(), "\t");
    }

    #[test]
    fn parses_quoted_with_decimal_escape() {
        // \009 is byte 9 (tab) — same as "\t".
        let s = parse("\"\\009\"").unwrap();
        assert_eq!(s.as_atom().unwrap(), "\t");
    }

    #[test]
    fn parses_empty_list() {
        let s = parse("()").unwrap();
        assert!(s.as_list().unwrap().is_empty());
    }

    #[test]
    fn parses_nested_sample() {
        // Mini sample mimicking proof structure.
        let s = parse("((plonk ((alpha ((inner (deadbeef cafebabe)))) (beta (1 2)))))").unwrap();
        let plonk = s.field("plonk").unwrap();
        let alpha = plonk.field("alpha").unwrap();
        let inner = alpha.field("inner").unwrap();
        let limbs = inner.as_list().unwrap();
        assert_eq!(limbs[0].as_atom().unwrap(), "deadbeef");
        assert_eq!(limbs[1].as_atom().unwrap(), "cafebabe");
    }

    #[test]
    fn rejects_trailing_garbage() {
        assert!(parse("(a) (b)").is_err());
    }

    #[test]
    fn rejects_unclosed_list() {
        assert!(parse("(a (b))").is_ok());
        assert!(parse("(a (b)").is_err());
    }
}
