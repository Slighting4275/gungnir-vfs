//! Randomized checks of the parsers that read files the user (or any program running as
//! the user) can write: `recently-used.xbel` (recent.rs) and `.trashinfo` files and trash
//! item names (trash.rs). Structure-aware: random bytes mixed with the fragments the
//! parsers look for. No input may panic, and every output must keep its invariants.

use gungnird::{recent, trash};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

const XBEL_PARTS: &[&[u8]] = &[
    b"<bookmark",
    b"</bookmark>",
    b"<bookmark href=\"file:///a\"/>",
    b" href=",
    b"\"",
    b"'",
    b">",
    b"/>",
    b"<",
    b"<!--",
    b"-->",
    b"<![CDATA[",
    b"]]>",
    b"<?xml",
    b"?>",
    b"&amp;",
    b"&lt;",
    b"&",
    b";",
    b"file://",
    b"%2f",
    b"%",
    b"%+f",
    b"%0",
    b"=",
    b" ",
    b"\n",
    b"\0",
    b"\xff",
];

const INFO_PARTS: &[&[u8]] = &[
    b"[Trash Info]",
    b"[Other]",
    b"[",
    b"Path=",
    b"DeletionDate=",
    b"2026-10-31T10:00:00",
    b"/home/u/f",
    b"%",
    b"%2",
    b"%2f",
    b"%00",
    b"%+f",
    b"%zz",
    b"\n",
    b"\r\n",
    b"\r",
    b"\0",
    b"..",
    b"/",
    b"\xc3",
];

fn build(rng: &mut Rng, parts: &[&[u8]], max: usize) -> Vec<u8> {
    let mut v = Vec::new();
    let n = rng.below(max) + 1;
    for _ in 0..n {
        if rng.below(4) == 0 {
            for _ in 0..rng.below(8) + 1 {
                v.push(rng.next() as u8);
            }
        } else {
            v.extend_from_slice(parts[rng.below(parts.len())]);
        }
    }
    v
}

#[test]
fn recent_parse_never_panics() {
    // The byte ranges' invariants are checked in recent.rs's own tests (private field).
    let mut rng = Rng(0x5eed_0001_dead_beef);
    for _ in 0..200_000 {
        let text = build(&mut rng, XBEL_PARTS, 24);
        for e in recent::parse(&text) {
            assert!(!e.uri.is_empty() || text.windows(4).any(|w| w == b"href"));
        }
    }
}

#[test]
fn recent_file_path_never_panics_and_never_yields_nul() {
    let mut rng = Rng(0x5eed_0002_dead_beef);
    for _ in 0..200_000 {
        let uri = build(&mut rng, XBEL_PARTS, 8);
        if let Some(p) = recent::file_path(&uri) {
            assert!(!p.contains(&0));
            assert_eq!(p.first(), Some(&b'/'));
        }
    }
}

#[test]
fn trash_parse_info_never_panics_and_paths_are_sane() {
    let mut rng = Rng(0x5eed_0003_dead_beef);
    for _ in 0..200_000 {
        let text = build(&mut rng, INFO_PARTS, 16);
        if let Some(info) = trash::parse_info(&text) {
            assert!(!info.path.is_empty());
            assert!(!info.path.contains(&0));
        }
    }
}

#[test]
fn trash_item_names_never_panic() {
    let mut rng = Rng(0x5eed_0004_dead_beef);
    let parts: &[&[u8]] = &[
        b"h", b"-", b"2f", b"+f", b"zz", b"/", b".", b"..", b"\0", b"a",
    ];
    for _ in 0..200_000 {
        let name = build(&mut rng, parts, 10);
        let _ = trash::valid_entry(&name);
        if let Some(p) = trash::volume_of(&name) {
            assert!(!p.as_os_str().is_empty() || name.starts_with(b"-"));
        }
    }
}

/// Escapes are two hex digits, nothing else: `u8::from_str_radix` also takes a sign, so
/// `%+f` decoded to 0x0f and one byte had two spellings. GLib rejects such escapes.
#[test]
fn escapes_with_a_sign_are_rejected() {
    assert_eq!(recent::file_path(b"file:///a%+fb"), None);
    assert_eq!(recent::file_path(b"file:///a%2fb"), Some(b"/a/b".to_vec()));
    assert_eq!(trash::parse_info(b"[Trash Info]\nPath=/a%+fb\n"), None);
    assert!(trash::parse_info(b"[Trash Info]\nPath=/a%2Fb\n").is_some());
    // A trash item name's volume part is hex too.
    assert_eq!(trash::volume_of(b"2f+f-x"), None);
    assert_eq!(
        trash::volume_of(b"2f6d-x").map(|p| p.into_os_string().into_encoded_bytes()),
        Some(b"/m".to_vec())
    );
}
