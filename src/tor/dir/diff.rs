//! Applying a consensus diff (dir-spec/directory-cache-operation.md section
//! 4.5, and the limited ed diff format of dir-spec/limited-ed-diff-format.md).
//!
//! Rather than send two and a half megabytes of consensus every hour, a cache
//! will answer with a few kilobytes of ed-style diff from a consensus the
//! client says it already has. The diff itself carries no signature: it is
//! bracketed by two digests, and the document that comes out of it still has
//! to pass the ordinary signature check before anything is believed. So the
//! worst a lying cache can do here is waste a round trip.

use std::io;

use super::consensus;
use super::netdoc;
use crate::ffi::hash::sha3_256;
use crate::util::{hex_decode, hex_encode, invalid_data};

const VERSION_LINE: &str = "network-status-diff-version 1";

/// Apply `diff` to `base`, returning the new document.
///
/// Every failure is an error and never a panic: a diff arrives from a relay we
/// have not authenticated, and the caller's answer to any complaint here is
/// simply to fetch the whole consensus instead.
#[allow(dead_code)] // Called from the consensus fetch path by the rest of M15.
pub fn apply(base: &str, diff: &str) -> io::Result<String> {
    let (diff_lines, _) = split_lines(diff);
    if diff_lines.first() != Some(&VERSION_LINE) {
        return Err(invalid_data("not a consensus diff: no version 1 header"));
    }
    let hash_line = diff_lines
        .get(1)
        .ok_or_else(|| invalid_data("consensus diff ends after its header"))?;
    let (from, to) = parse_hash_line(hash_line)?;

    // The "from" digest covers the signed part only, so that a diff still
    // applies to a copy of the old consensus carrying a different set of
    // signatures -- which is why a diff's first command deletes them all.
    let ours = signed_part_digest(base);
    if !from.eq_ignore_ascii_case(&ours) {
        return Err(invalid_data(format!(
            "consensus diff is from {from}, but our consensus is {ours}"
        )));
    }

    let (lines, trailing_newline) = split_lines(base);
    // The commands come in descending order and address the base document, so
    // the result is assembled from the back: `kept` holds it reversed, and `j`
    // is how much of the base is still untouched.
    let mut kept: Vec<&str> = Vec::with_capacity(lines.len());
    let mut j = lines.len();
    let mut cursor = 2;
    while cursor < diff_lines.len() {
        let command = parse_command(&diff_lines, &mut cursor, lines.len())?;
        if command.end > lines.len() {
            return Err(invalid_data(format!(
                "consensus diff command {:?} runs past the end of a {}-line document",
                command.text,
                lines.len()
            )));
        }
        if command.end > j {
            return Err(invalid_data(format!(
                "consensus diff command {:?} is not in descending line order",
                command.text
            )));
        }
        // Between this hunk and the one already handled, the base is copied
        // through unchanged. Line numbers are 1-based, so `end` is also the
        // count of base lines up to and including the last one this hunk
        // covers.
        kept.extend(lines[command.end..j].iter().rev().copied());
        kept.extend(command.insert.iter().rev().copied());
        j = match command.action {
            // An append leaves the line it names in place; a delete or a
            // change consumes the whole range starting at it.
            Action::Append => command.start,
            Action::Delete | Action::Change => command.start - 1,
        };
    }
    kept.extend(lines[..j].iter().rev().copied());
    kept.reverse();

    let result = join_lines(&kept, trailing_newline);
    let digest = document_digest(&result);
    if !to.eq_ignore_ascii_case(&digest) {
        return Err(invalid_data(format!(
            "consensus diff promised {to} but produced {digest}"
        )));
    }
    Ok(result)
}

/// The SHA3-256 of a document, hex-encoded uppercase, the way the `hash` line
/// and the `X-Or-Diff-From-Consensus` header spell a digest.
///
/// This is a diff's "to" digest, which covers the whole resulting consensus.
/// The "from" digest, and the header, cover the signed part only: see
/// [`signed_part_digest`].
pub fn document_digest(text: &str) -> String {
    hex_encode(&sha3_256(text.as_bytes()))
}

/// The digest of the *signed part* of a consensus: what a client sends in
/// `X-Or-Diff-From-Consensus`, and what a diff's "from" field names.
///
/// dir-spec is explicit that this digest, unlike the "to" digest, stops after
/// the first `directory-signature` keyword and its space. A document with no
/// signature at all -- only the synthetic ones in the tests below -- has no
/// signed part, and is hashed whole.
pub fn signed_part_digest(text: &str) -> String {
    let end = consensus::signed_length(text).unwrap_or(text.len());
    hex_encode(&sha3_256(&text.as_bytes()[..end]))
}

/// The `hash` line's two digests, still hex, checked for shape so that a
/// malformed diff is reported as one rather than as a digest mismatch.
fn parse_hash_line(line: &str) -> io::Result<(&str, &str)> {
    let bad = || invalid_data(format!("consensus diff has a bad hash line {line:?}"));
    let args = netdoc::item_args(line, "hash").ok_or_else(bad)?;
    let mut fields = args.split(' ');
    let (Some(from), Some(to), None) = (fields.next(), fields.next(), fields.next()) else {
        return Err(bad());
    };
    for digest in [from, to] {
        if !matches!(hex_decode(digest), Ok(bytes) if bytes.len() == 32) {
            return Err(bad());
        }
    }
    Ok((from, to))
}

enum Action {
    Delete,
    Change,
    Append,
}

struct Command<'a> {
    /// The command line itself, kept for error messages.
    text: &'a str,
    /// First line of the range, 1-based. Zero only for `0a`, which ed reads as
    /// "insert before the first line".
    start: usize,
    /// Last line of the range, inclusive; equal to `start` for `a`.
    end: usize,
    action: Action,
    /// The block that follows an `a` or a `c`.
    insert: Vec<&'a str>,
}

/// Read one command and its block, advancing `cursor` past both. `last` is the
/// number of lines in the base document, which is what `$` stands for.
fn parse_command<'a>(
    lines: &[&'a str],
    cursor: &mut usize,
    last: usize,
) -> io::Result<Command<'a>> {
    let text = lines[*cursor];
    *cursor += 1;
    let bad = || invalid_data(format!("unsupported consensus diff command {text:?}"));

    // Only the three commands of the limited format are accepted; anything
    // else -- ed's `i`, `s` or `m`, or a bare address -- is a diff we refuse.
    let action = match text.as_bytes().last() {
        Some(b'd') => Action::Delete,
        Some(b'c') => Action::Change,
        Some(b'a') => Action::Append,
        _ => return Err(bad()),
    };
    let addresses = &text[..text.len() - 1];
    let (start, end) = match addresses.split_once(',') {
        Some((first, second)) => {
            // Appending happens after a single line; a range would leave it
            // ambiguous which end of it the block belongs after.
            if matches!(action, Action::Append) {
                return Err(bad());
            }
            (
                parse_address(first, last).ok_or_else(bad)?,
                parse_address(second, last).ok_or_else(bad)?,
            )
        }
        None => {
            let only = parse_address(addresses, last).ok_or_else(bad)?;
            (only, only)
        }
    };
    if start > end || (start == 0 && !matches!(action, Action::Append)) {
        return Err(bad());
    }

    let mut insert = Vec::new();
    if !matches!(action, Action::Delete) {
        loop {
            let line = *lines.get(*cursor).ok_or_else(|| {
                invalid_data(format!(
                    "consensus diff block after {text:?} has no \".\" terminator"
                ))
            })?;
            *cursor += 1;
            if line == "." {
                break;
            }
            // A dot followed by nothing but whitespace would end the block for
            // a parser that trims and not for one that does not; the spec has
            // us reject a diff that contains one rather than guess.
            if let Some(rest) = line.strip_prefix('.') {
                if !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_whitespace()) {
                    return Err(invalid_data("consensus diff inserts a dotted blank line"));
                }
            }
            insert.push(line);
        }
    }

    Ok(Command {
        text,
        start,
        end,
        action,
        insert,
    })
}

/// One address of a command: a decimal line number, or `$` for the last line.
fn parse_address(field: &str, last: usize) -> Option<usize> {
    if field == "$" {
        return Some(last);
    }
    // `usize::from_str` would also take a leading `+`, and an empty field
    // would make `,4d` look like a range; neither is an ed address.
    if field.is_empty() || !field.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    field.parse().ok()
}

/// Split a document into lines, remembering whether it ended with a newline.
///
/// `str::lines` cannot be used here: it reads "a\nb" and "a\nb\n" as the same
/// two lines, so a document rebuilt from it would not hash to what the diff
/// promised. What this returns goes back through [`join_lines`] byte for byte.
fn split_lines(text: &str) -> (Vec<&str>, bool) {
    match text.strip_suffix('\n') {
        Some(body) => (body.split('\n').collect(), true),
        None if text.is_empty() => (Vec::new(), false),
        None => (text.split('\n').collect(), false),
    }
}

fn join_lines(lines: &[&str], trailing_newline: bool) -> String {
    if lines.is_empty() {
        return String::new();
    }
    let mut out = String::with_capacity(lines.iter().map(|line| line.len() + 1).sum());
    for (i, line) in lines.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out.push_str(line);
    }
    if trailing_newline {
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "line1\nline2\nline3\nline4\nline5\n";

    /// A well-formed diff whose header promises exactly `body`'s effect.
    fn diff_for(base: &str, expected: &str, body: &str) -> String {
        format!(
            "{VERSION_LINE}\nhash {} {}\n{body}",
            signed_part_digest(base),
            document_digest(expected)
        )
    }

    fn check(base: &str, body: &str, expected: &str) {
        let diff = diff_for(base, expected, body);
        match apply(base, &diff) {
            Ok(result) => assert_eq!(result, expected, "diff body {body:?}"),
            Err(e) => panic!("diff body {body:?} should have applied: {e}"),
        }
    }

    #[test]
    fn deletes_lines() {
        check(BASE, "3d\n", "line1\nline2\nline4\nline5\n");
        check(BASE, "2,4d\n", "line1\nline5\n");
        check(BASE, "1,5d\n", "");
    }

    #[test]
    fn appends_blocks() {
        check(
            BASE,
            "2a\nnew\n.\n",
            "line1\nline2\nnew\nline3\nline4\nline5\n",
        );
        check(
            BASE,
            "5a\nsix\nseven\n.\n",
            "line1\nline2\nline3\nline4\nline5\nsix\nseven\n",
        );
        // `0a` is how ed inserts before the first line.
        check(
            BASE,
            "0a\nzero\n.\n",
            "zero\nline1\nline2\nline3\nline4\nline5\n",
        );
    }

    #[test]
    fn changes_lines() {
        check(
            BASE,
            "3c\nthird\n.\n",
            "line1\nline2\nthird\nline4\nline5\n",
        );
        check(BASE, "2,4c\nX\nY\n.\n", "line1\nX\nY\nline5\n");
        // A change may insert fewer lines than it removes, or more.
        check(BASE, "1,5c\nonly\n.\n", "only\n");
    }

    #[test]
    fn resolves_dollar_as_the_last_line() {
        check(BASE, "$d\n", "line1\nline2\nline3\nline4\n");
        check(BASE, "3,$d\n", "line1\nline2\n");
        check(BASE, "$c\nend\n.\n", "line1\nline2\nline3\nline4\nend\n");
    }

    #[test]
    fn applies_several_hunks_in_descending_order() {
        check(
            BASE,
            "5c\nlast\n.\n3d\n1a\nextra\n.\n",
            "line1\nextra\nline2\nline4\nlast\n",
        );
    }

    #[test]
    fn rejects_ascending_commands() {
        // The same two hunks as above, in the order ed would print them if it
        // were not required to work backwards.
        let expected = "line1\nline2\nline4\nlast\n";
        let diff = diff_for(BASE, expected, "3d\n5c\nlast\n.\n");
        let e = apply(BASE, &diff).expect_err("ascending commands must be refused");
        assert!(
            e.to_string().contains("descending"),
            "unexpected message: {e}"
        );
    }

    #[test]
    fn rejects_a_from_digest_that_is_not_ours() {
        let expected = "line1\nline2\nline4\nline5\n";
        let diff = diff_for("some other consensus\n", expected, "3d\n");
        let e = apply(BASE, &diff).expect_err("a diff for another consensus must be refused");
        assert!(e.to_string().contains("our consensus"), "message: {e}");
    }

    #[test]
    fn rejects_a_to_digest_the_result_does_not_match() {
        // The commands are fine; the header claims a different outcome.
        let diff = diff_for(BASE, "something else\n", "3d\n");
        let e = apply(BASE, &diff).expect_err("a mis-promised result must be refused");
        assert!(e.to_string().contains("promised"), "message: {e}");
    }

    #[test]
    fn hashes_only_the_signed_part_of_the_from_document() {
        let signed = "network-status-version 3 microdesc\nline2\ndirectory-signature ";
        let base = format!(
            "{signed}sha256 AABB CCDD\n\
             -----BEGIN SIGNATURE-----\naGk=\n-----END SIGNATURE-----\n"
        );
        assert_eq!(signed_part_digest(&base), document_digest(signed));
        assert_ne!(signed_part_digest(&base), document_digest(&base));

        // A cache that kept a differently signed copy of the same consensus
        // still hands us a diff we can apply.
        let expected = "network-status-version 3 microdesc\nline2\nfresh\n";
        let diff = format!(
            "{VERSION_LINE}\nhash {} {}\n3,$d\n2a\nfresh\n.\n",
            document_digest(signed),
            document_digest(expected)
        );
        assert_eq!(apply(&base, &diff).unwrap(), expected);
    }

    #[test]
    fn preserves_the_exact_bytes_of_the_base() {
        // Splitting and rejoining is the identity, whatever the document does
        // at its end.
        for text in ["", "\n", "a", "a\n", "a\nb", "a\nb\n", "a\n\nb\n\n"] {
            let (lines, trailing) = split_lines(text);
            assert_eq!(join_lines(&lines, trailing), text, "round trip {text:?}");
        }

        // A diff with no commands gives the document back untouched, byte for
        // byte, trailing newline and all.
        assert_eq!(apply(BASE, &diff_for(BASE, BASE, "")).unwrap(), BASE);

        // A base with no trailing newline keeps having none.
        let ragged = "a\nb";
        check(ragged, "1c\nX\n.\n", "X\nb");
        check(ragged, "2a\nc\n.\n", "a\nb\nc");
    }

    #[test]
    fn rejects_malformed_diffs() {
        let expected = "line1\nline2\nline4\nline5\n";
        for body in [
            "3c\nreplacement\n", // a block with no "." terminator
            "3a\n",              // a block that ends before it begins
            "xd\n",              // a non-numeric line number
            "9d\n",              // past the end of the document
            "3,$,4d\n",          // three addresses
            "3\n",               // an address with no command
            "3s/a/b/\n",         // a command outside the subset
            "0d\n",              // ed line numbers start at one
            "4,2d\n",            // a reversed range
            "-1d\n",             // not an ed address
            "2,3a\nnew\n.\n",    // append takes a single address
            "3c\n. \n.\n",       // a dotted blank line
            "1,$d\n0a\ntext\n",  // truncated after the last command
        ] {
            let diff = diff_for(BASE, expected, body);
            assert!(
                apply(BASE, &diff).is_err(),
                "body {body:?} should have been refused"
            );
        }

        // Headers, rather than commands.
        for diff in [
            "",
            "\n",
            VERSION_LINE,
            "network-status-diff-version 2\nhash A B\n",
            "network-status-version 3 microdesc\n",
            &format!("{VERSION_LINE}\n"),
            &format!("{VERSION_LINE}\nhash\n"),
            &format!("{VERSION_LINE}\nhash zz zz\n"),
            &format!("{VERSION_LINE}\nhash {}\n", document_digest(BASE)),
            &format!(
                "{VERSION_LINE}\nhash {} {} extra\n",
                signed_part_digest(BASE),
                document_digest(BASE)
            ),
        ] {
            assert!(
                apply(BASE, diff).is_err(),
                "header {diff:?} should have been refused"
            );
        }
    }
}
