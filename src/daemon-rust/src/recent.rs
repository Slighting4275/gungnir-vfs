//! Recent files (milestone 9): `recently-used.xbel` in the user's data directory, the
//! file GTK writes. Listing reads it; forgetting an entry rewrites it atomically (temp
//! file, fsync, rename), so a reader sees the old or the new list, never half of one.
//!
//! Writers serialise on `<file>.lock` with a bounded wait, which runs out as `Busy`:
//! never an unbounded block. GTK does not take that lock, so a GTK write racing ours can
//! lose its entry or ours; GTK rewrites the whole file on every change anyway.

use std::{
    fs,
    io::{self, Write},
    os::unix::{fs::OpenOptionsExt, io::AsRawFd},
    path::Path,
    thread,
    time::{Duration, Instant},
};

/// Largest list read: a bigger one is refused, not parsed into memory.
pub const XBEL_MAX: u64 = 32 << 20;
const LOCK_WAIT: Duration = Duration::from_secs(1);

/// One bookmark.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The URI as written, XML entities decoded.
    pub uri: Vec<u8>,
    /// The bookmark's byte range in the file.
    range: (usize, usize),
}

fn attr<'a>(tag: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    let mut i = 0;
    while let Some(off) = find(&tag[i..], name) {
        let at = i + off;
        let boundary = at == 0 || tag[at - 1].is_ascii_whitespace();
        let rest = &tag[at + name.len()..];
        if boundary && rest.first() == Some(&b'=') {
            let quote = *rest.get(1)?;
            if quote == b'"' || quote == b'\'' {
                let body = &rest[2..];
                let end = body.iter().position(|&b| b == quote)?;
                return Some(&body[..end]);
            }
        }
        i = at + name.len();
    }
    None
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn xml_decode(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    'outer: while i < s.len() {
        for (ent, ch) in [
            (&b"&amp;"[..], b'&'),
            (b"&lt;", b'<'),
            (b"&gt;", b'>'),
            (b"&quot;", b'"'),
            (b"&apos;", b'\''),
        ] {
            if s[i..].starts_with(ent) {
                out.push(ch);
                i += ent.len();
                continue 'outer;
            }
        }
        out.push(s[i]);
        i += 1;
    }
    out
}

/// The bookmarks of `text`, in file order. Anything that is not a well-formed
/// `<bookmark ...>` is skipped, never an error.
#[must_use]
pub fn parse(text: &[u8]) -> Vec<Entry> {
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(off) = find(&text[i..], b"<bookmark") {
        let start = i + off;
        let after = text.get(start + 9).copied();
        if !after.is_some_and(|b| b.is_ascii_whitespace()) {
            i = start + 9;
            continue;
        }
        let Some(tag_len) = text[start..].iter().position(|&b| b == b'>') else {
            break;
        };
        let tag = &text[start + 9..start + tag_len];
        let end = if tag.last() == Some(&b'/') {
            start + tag_len + 1
        } else if let Some(c) = find(&text[start..], b"</bookmark>") {
            start + c + b"</bookmark>".len()
        } else {
            break;
        };
        if let Some(href) = attr(tag, b"href") {
            out.push(Entry {
                uri: xml_decode(href),
                range: (start, end),
            });
        }
        i = end;
    }
    out
}

/// A `file://` URI's absolute path, percent-decoded; `None` for anything else.
#[must_use]
pub fn file_path(uri: &[u8]) -> Option<Vec<u8>> {
    let rest = uri.strip_prefix(b"file://")?;
    if rest.first() != Some(&b'/') {
        return None;
    }
    let mut out = Vec::with_capacity(rest.len());
    let mut i = 0;
    while i < rest.len() {
        if rest[i] == b'%' {
            let h = rest.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(std::str::from_utf8(h).ok()?, 16).ok()?);
            i += 3;
        } else {
            out.push(rest[i]);
            i += 1;
        }
    }
    (!out.contains(&0)).then_some(out)
}

/// Read the list.
///
/// # Errors
/// It is too big or unreadable; a missing list is an empty one.
pub fn load(path: &Path) -> io::Result<Vec<u8>> {
    match fs::metadata(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
        Ok(m) if m.len() > XBEL_MAX => return Err(io::Error::from_raw_os_error(libc::EFBIG)),
        Ok(_) => {}
    }
    fs::read(path)
}

/// Why [`forget`] failed.
#[derive(Debug)]
pub enum ForgetError {
    /// Another writer held the lock past the bound.
    Busy,
    NotFound,
    Io(io::Error),
}

impl From<io::Error> for ForgetError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// Remove every bookmark with `uri`. The target file itself is not touched.
///
/// # Errors
/// See [`ForgetError`].
pub fn forget(path: &Path, uri: &[u8]) -> Result<(), ForgetError> {
    let mut lock_path = path.as_os_str().to_owned();
    lock_path.push(".lock");
    let lock = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(&lock_path)?;
    let t0 = Instant::now();
    loop {
        // SAFETY: a valid fd; LOCK_NB never blocks.
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            break;
        }
        if t0.elapsed() >= LOCK_WAIT {
            return Err(ForgetError::Busy);
        }
        thread::sleep(Duration::from_millis(10));
    }
    let text = load(path)?;
    let hits: Vec<_> = parse(&text).into_iter().filter(|e| e.uri == uri).collect();
    if hits.is_empty() {
        return Err(ForgetError::NotFound);
    }
    let mut out = Vec::with_capacity(text.len());
    let mut at = 0;
    for e in &hits {
        out.extend_from_slice(&text[at..e.range.0]);
        at = e.range.1;
    }
    out.extend_from_slice(&text[at..]);
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(format!(".gungnir-{}", std::process::id()));
    let r = (|| -> io::Result<()> {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(&out)?;
        f.sync_all()?;
        fs::rename(&tmp, path)
    })();
    if r.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    Ok(r?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    const XBEL: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<xbel version="1.0">
  <bookmark href="file:///home/u/a%20b.txt" added="x" modified="y" visited="z">
    <info><metadata owner="o"><mime:mime-type type="text/plain"/></metadata></info>
  </bookmark>
  <bookmark href="file:///home/u/q&amp;a.txt" added="x"/>
  <bookmarkish href="file:///no"/>
  <bookmark added="no href"/>
  <bookmark href='https://example.invalid/x' added="x"></bookmark>
</xbel>
"#;

    fn tmp(tag: &str) -> PathBuf {
        let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.build/tmp");
        fs::create_dir_all(&base).unwrap();
        base.join(format!("recent-{tag}-{}.xbel", std::process::id()))
    }

    #[test]
    fn parsing_keeps_bookmarks_and_skips_the_rest() {
        let e = parse(XBEL.as_bytes());
        let uris: Vec<_> = e.iter().map(|x| x.uri.as_slice()).collect();
        assert_eq!(
            uris,
            [
                &b"file:///home/u/a%20b.txt"[..],
                b"file:///home/u/q&a.txt",
                b"https://example.invalid/x"
            ]
        );
        assert!(parse(b"<bookmark href=\"x\"").is_empty());
        assert!(parse(b"").is_empty());
        assert!(parse(b"\xff\xfe<bookmark").is_empty());
    }

    #[test]
    fn file_uris_decode() {
        assert_eq!(file_path(b"file:///a%20b").unwrap(), b"/a b");
        assert!(file_path(b"https://x/y").is_none());
        assert!(file_path(b"file://host/y").is_none());
        assert!(file_path(b"file:///a%00b").is_none());
        assert!(file_path(b"file:///a%z").is_none());
    }

    #[test]
    fn forgetting_removes_only_that_bookmark() {
        let p = tmp("forget");
        fs::write(&p, XBEL).unwrap();
        forget(&p, b"file:///home/u/a%20b.txt").unwrap();
        let left = fs::read(&p).unwrap();
        assert_eq!(parse(&left).len(), 2);
        assert!(find(&left, b"<xbel version").is_some());
        assert!(find(&left, b"</xbel>").is_some());
        assert!(matches!(
            forget(&p, b"file:///none"),
            Err(ForgetError::NotFound)
        ));
        let _ = fs::remove_file(&p);
        let _ = fs::remove_file(p.with_extension("xbel.lock"));
    }

    /// D-003: a held lock ends in Busy within the bound, not a block.
    #[test]
    fn a_held_lock_is_busy_in_bounded_time() {
        let p = tmp("busy");
        fs::write(&p, XBEL).unwrap();
        let mut lp = p.as_os_str().to_owned();
        lp.push(".lock");
        let l = fs::File::create(&lp).unwrap();
        // SAFETY: a valid fd.
        assert_eq!(unsafe { libc::flock(l.as_raw_fd(), libc::LOCK_EX) }, 0);
        let t0 = Instant::now();
        assert!(matches!(forget(&p, b"file:///x"), Err(ForgetError::Busy)));
        assert!(t0.elapsed() < Duration::from_secs(3));
        let _ = fs::remove_file(&p);
        let _ = fs::remove_file(&lp);
    }
}
