//! Recent files (milestone 9): `recently-used.xbel` in the user's data directory, the
//! file GTK writes. Listing reads it; forgetting an entry rewrites it atomically (temp
//! file, fsync, rename), so a reader sees the old or the new list, never half of one.
//!
//! Writers serialise on `<file>.lock` with a bounded wait, which runs out as `Busy`:
//! never an unbounded block. GTK does not take that lock, so a GTK write racing ours can
//! lose its entry or ours; GTK rewrites the whole file on every change anyway.

use std::{
    fs,
    io::{self, Read, Write},
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

/// The value of attribute `name`, walking the attributes in order: a value is opaque,
/// whatever it says, and anything that is not `name=<quoted value>` ends the walk.
fn attr<'a>(tag: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    let mut rest = tag;
    loop {
        rest = rest.trim_ascii_start();
        let eq = rest.iter().position(|&b| b == b'=')?;
        let key = rest[..eq].trim_ascii_end();
        rest = rest[eq + 1..].trim_ascii_start();
        let (&quote, body) = rest.split_first()?;
        if quote != b'"' && quote != b'\'' {
            return None;
        }
        let end = body.iter().position(|&b| b == quote)?;
        if key == name {
            return Some(&body[..end]);
        }
        rest = &body[end + 1..];
    }
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

/// Offset of the `>` ending the tag at the start of `text`: XML allows `>` inside a quoted
/// attribute value.
fn tag_end(text: &[u8]) -> Option<usize> {
    let mut quote = None;
    for (i, &b) in text.iter().enumerate() {
        match quote {
            Some(q) if b == q => quote = None,
            Some(_) => {}
            None if b == b'"' || b == b'\'' => quote = Some(b),
            None if b == b'>' => return Some(i),
            None => {}
        }
    }
    None
}

/// The next real tag at or after `from`: `(start, end past its >)`. Comments, CDATA and
/// processing instructions are not markup, whatever they contain.
fn next_tag(text: &[u8], mut from: usize) -> Option<(usize, usize)> {
    loop {
        let at = from + find(text.get(from..)?, b"<")?;
        let rest = &text[at..];
        let close: Option<&[u8]> = if rest.starts_with(b"<!--") {
            Some(b"-->")
        } else if rest.starts_with(b"<![CDATA[") {
            Some(b"]]>")
        } else if rest.starts_with(b"<?") {
            Some(b"?>")
        } else {
            None
        };
        match close {
            Some(c) => from = at + find(rest, c)? + c.len(),
            None => return Some((at, at + tag_end(rest)? + 1)),
        }
    }
}

/// Whether the tag in `tag` (from its `<`) is `name`, not merely starting with it.
fn tag_is(tag: &[u8], name: &[u8]) -> bool {
    tag.strip_prefix(name)
        .and_then(|r| r.first())
        .is_some_and(|&b| b.is_ascii_whitespace() || b == b'>' || b == b'/')
}

/// The bookmarks of `text`, in file order. Anything that is not a well-formed
/// `<bookmark ...>` is skipped, never an error.
#[must_use]
pub fn parse(text: &[u8]) -> Vec<Entry> {
    let mut out = Vec::new();
    let mut i = 0;
    while let Some((start, close)) = next_tag(text, i) {
        i = close;
        if !tag_is(&text[start..close], b"<bookmark") {
            continue;
        }
        let tag = &text[start + 9..close - 1];
        let end = if tag.last() == Some(&b'/') {
            close
        } else {
            let mut from = close;
            loop {
                let Some((a, b)) = next_tag(text, from) else {
                    return out;
                };
                if tag_is(&text[a..b], b"</bookmark") {
                    break b;
                }
                from = b;
            }
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
    let f = match fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(path)
    {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        r => r?,
    };
    if !f.metadata()?.is_file() {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    // The cap counts bytes read: metadata says nothing about what a read returns.
    let mut out = Vec::new();
    f.take(XBEL_MAX + 1).read_to_end(&mut out)?;
    if out.len() as u64 > XBEL_MAX {
        return Err(io::Error::from_raw_os_error(libc::EFBIG));
    }
    Ok(out)
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

fn with_lock<R>(path: &Path, f: impl FnOnce() -> Result<R, ForgetError>) -> Result<R, ForgetError> {
    let mut lock_path = path.as_os_str().to_owned();
    lock_path.push(".lock");
    let lock = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        // A FIFO here must not hold the request; the lock is ours, never a link.
        .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
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
    f()
}

fn write_atomic(path: &Path, out: &[u8]) -> io::Result<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(format!(".gungnir-{}", std::process::id()));
    // Under the lock, so anything here is what a crash left.
    let _ = fs::remove_file(&tmp);
    let r = (|| -> io::Result<()> {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(out)?;
        f.sync_all()?;
        fs::rename(&tmp, path)
    })();
    if r.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    r
}

/// Remove every bookmark with `uri`. The target file itself is not touched.
///
/// # Errors
/// See [`ForgetError`].
pub fn forget(path: &Path, uri: &[u8]) -> Result<(), ForgetError> {
    with_lock(path, || {
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
        Ok(write_atomic(path, &out)?)
    })
}

/// Clear every bookmark from the list. The target files are not touched.
///
/// # Errors
/// See [`ForgetError`].
pub fn clear(path: &Path) -> Result<(), ForgetError> {
    with_lock(path, || {
        let text = load(path)?;
        if text.is_empty() {
            return Ok(());
        }
        let hits = parse(&text);
        if hits.is_empty() {
            return Ok(());
        }
        let mut out = Vec::with_capacity(text.len());
        let mut at = 0;
        for e in &hits {
            out.extend_from_slice(&text[at..e.range.0]);
            at = e.range.1;
        }
        out.extend_from_slice(&text[at..]);
        Ok(write_atomic(path, &out)?)
    })
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

    #[test]
    fn clearing_removes_all_bookmarks() {
        let p = tmp("clear");
        fs::write(&p, XBEL).unwrap();
        clear(&p).unwrap();
        let left = fs::read(&p).unwrap();
        assert!(parse(&left).is_empty());
        assert!(find(&left, b"<xbel version").is_some());
        assert!(find(&left, b"</xbel>").is_some());
        // Clearing an already empty file succeeds idempotently
        clear(&p).unwrap();
        let _ = fs::remove_file(&p);
        let _ = fs::remove_file(p.with_extension("xbel.lock"));
    }

    /// XML allows `>` inside an attribute value. A tag cut there must not swallow the next
    /// bookmark, or forgetting one entry would lose another.
    #[test]
    fn a_greater_than_in_an_attribute_keeps_bookmarks_apart() {
        let text = br#"<xbel>
<bookmark href="file:///a" title="x>y"/>
<bookmark href="file:///b" added="1"><info/></bookmark>
</xbel>
"#;
        let e = parse(text);
        assert_eq!(e.len(), 2, "{e:?}");
        let p = tmp("gt");
        fs::write(&p, text).unwrap();
        forget(&p, b"file:///a").unwrap();
        let left = parse(&fs::read(&p).unwrap());
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].uri, b"file:///b");
        let _ = fs::remove_file(&p);
        let _ = fs::remove_file(p.with_extension("xbel.lock"));
    }

    /// An attribute's value is not attributes: `href` in a title selects nothing.
    #[test]
    fn a_value_cannot_pose_as_an_attribute() {
        let text = br#"<xbel><bookmark title="x href='file:///bait'" href="file:///real"/></xbel>"#;
        let e = parse(text);
        assert_eq!(e.len(), 1, "{e:?}");
        assert_eq!(e[0].uri, b"file:///real");
    }

    /// A bookmark inside a comment is no bookmark, and cannot pair with a real close tag.
    #[test]
    fn comments_hide_bookmarks() {
        let text = br#"<xbel>
<!-- <bookmark href="file:///bait"> -->
<bookmark href="file:///kept"></bookmark>
</xbel>
"#;
        let e = parse(text);
        assert_eq!(e.len(), 1, "{e:?}");
        assert_eq!(e[0].uri, b"file:///kept");
        let p = tmp("comment");
        fs::write(&p, text).unwrap();
        assert!(matches!(
            forget(&p, b"file:///bait"),
            Err(ForgetError::NotFound)
        ));
        assert_eq!(fs::read(&p).unwrap(), text);
        let _ = fs::remove_file(&p);
        let _ = fs::remove_file(p.with_extension("xbel.lock"));
    }

    /// A FIFO or device in the list's place is refused, not read for ever.
    #[test]
    fn only_a_regular_file_is_read() {
        let p = tmp("dev");
        std::os::unix::fs::symlink("/dev/zero", &p).unwrap();
        assert!(load(&p).is_err());
        let _ = fs::remove_file(&p);
        let c = std::ffi::CString::new(p.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: a valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        assert!(load(&p).is_err());
        let _ = fs::remove_file(&p);
    }

    /// A temp file left by a crash under the same pid must not block every later forget.
    #[test]
    fn a_stale_temp_file_does_not_stop_a_forget() {
        let p = tmp("stale");
        fs::write(&p, XBEL).unwrap();
        let mut t = p.as_os_str().to_owned();
        t.push(format!(".gungnir-{}", std::process::id()));
        fs::write(&t, b"leftover").unwrap();
        forget(&p, b"file:///home/u/a%20b.txt").unwrap();
        assert!(!Path::new(&t).exists());
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
