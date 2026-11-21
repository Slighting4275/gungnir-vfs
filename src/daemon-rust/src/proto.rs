//! The wire protocol's numbers (protocol v2): the handshake, the shared-memory layout,
//! every slot kind, the one status space every reply shares, and the reply envelope.
//! Each service defines its payloads; none defines a kind or a status.
//!
//! The values are checked against `protocol/wire.txt` at the repo root, which the Zig
//! client's `proto.zig` is checked against too: a value that drifts on either side fails
//! that side's tests.

// Handshake frames on the control socket.
/// `b"GNGR"` read as a little-endian u32. Starts every frame and the shared-memory header.
pub const MAGIC: u32 = 0x5247_4E47;
/// Bumped for every layout change; a client speaking another version gets a reject
/// frame with [`STATUS_BAD_VERSION`] and no ring.
pub const VERSION: u16 = 2;
pub const FRAME_LEN: usize = 16;
pub const KIND_HELLO: u16 = 1;
pub const KIND_ACK: u16 = 2;
pub const KIND_REJECT: u16 = 3;
pub const STATUS_OK: u32 = 0;
pub const STATUS_BAD_MAGIC: u32 = 1;
pub const STATUS_BAD_VERSION: u32 = 2;
pub const STATUS_BAD_KIND: u32 = 3;

// Shared memory.
pub const SLOT_COUNT: u32 = 32;
pub const SLOT_SIZE: usize = 4096;
/// Slot header: kind u32 | len u32 | seq u64.
pub const SLOT_HEADER: usize = 16;
pub const PAYLOAD_MAX: usize = SLOT_SIZE - SLOT_HEADER;
pub const SHM_SIZE: usize = 4096 + 2 * SLOT_COUNT as usize * SLOT_SIZE;

// Slot kinds.
pub const MSG_PING: u32 = 1;
pub const MSG_PONG: u32 = 2;
pub const MSG_MD_IDENTIFY: u32 = 16;
pub const MSG_MD_GET: u32 = 17;
pub const MSG_MD_SET: u32 = 18;
pub const MSG_MD_UNSET: u32 = 19;
pub const MSG_MD_LIST: u32 = 20;
pub const MSG_MD_REMOVED: u32 = 21;
pub const MSG_MD_MOVED: u32 = 22;
pub const MSG_HEALTH_QUERY: u32 = 23;
pub const MSG_HEALTH_SUBSCRIBE: u32 = 24;
pub const MSG_OP_START: u32 = 25;
pub const MSG_OP_CANCEL: u32 = 26;
/// The reply to every request: `status u32 | body` ([`reply_payload`]).
pub const MSG_REPLY: u32 = 32;
/// Daemon -> client, unsolicited, `seq` 0.
pub const MSG_HEALTH_EVENT: u32 = 33;
pub const MSG_OP_PROGRESS: u32 = 34;
pub const MSG_OP_DONE: u32 = 35;
pub const MSG_VFS_LIST: u32 = 40;
pub const MSG_VFS_DELETE: u32 = 41;
pub const MSG_VFS_RESTORE: u32 = 42;
pub const MSG_TRASH_EMPTY: u32 = 43;
/// Sent while an op is under way (same seq, no payload): the client's silence bound
/// covers everything else, and an op may take as long as it makes progress.
pub const MSG_VFS_BEAT: u32 = 44;
/// One item by name, without listing the rest.
pub const MSG_VFS_STAT: u32 = 45;
/// What is in a trashed folder.
pub const MSG_VFS_CHILDREN: u32 = 46;
/// A number that changes when a scheme's list does.
pub const MSG_VFS_STAMP: u32 = 47;

// Statuses: the first u32 of every reply body, and of an op's done.
pub const ST_OK: u32 = 0;
pub const ST_NOT_FOUND: u32 = 1;
pub const ST_BUSY: u32 = 2;
pub const ST_TIMEOUT: u32 = 3;
pub const ST_SUSPECT_MOUNT: u32 = 4;
pub const ST_NO_SUCH_FILE: u32 = 5;
pub const ST_BAD_REQUEST: u32 = 6;
pub const ST_KEY_TOO_LONG: u32 = 7;
pub const ST_VALUE_TOO_LARGE: u32 = 8;
pub const ST_TOO_MANY_KEYS: u32 = 9;
pub const ST_BAD_UTF8: u32 = 10;
pub const ST_IO_ERROR: u32 = 11;
pub const ST_DB_ERROR: u32 = 12;
pub const ST_UNSUPPORTED: u32 = 13;
pub const ST_CANCELLED: u32 = 14;
/// A system error; the body (after the status) starts with `errno i32` ([`os_error`]).
pub const ST_OS_ERROR: u32 = 15;
pub const ST_WOULD_RECURSE: u32 = 16;
/// A mount inside the item: retryable once it is unmounted.
pub const ST_MOUNT_INSIDE: u32 = 17;
pub const ST_NOT_EMPTY: u32 = 18;

// Schemes of the trash and recent kinds.
pub const SCHEME_TRASH: u8 = 0;
pub const SCHEME_RECENT: u8 = 1;

// What a listed trash or recent item is (the `kind u8` of a list entry).
pub const KIND_FILE: u8 = 1;
pub const KIND_DIR: u8 = 2;
pub const KIND_SYMLINK: u8 = 3;
pub const KIND_SPECIAL: u8 = 4;

/// Reply payload: `status u32 | body`.
#[must_use]
pub fn reply_payload(status: u32, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&status.to_le_bytes());
    out.extend_from_slice(body);
    out
}

/// Reply payload of [`ST_OS_ERROR`]: `status | errno i32`.
#[must_use]
pub fn os_error(errno: i32) -> Vec<u8> {
    reply_payload(ST_OS_ERROR, &errno.to_le_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    const WIRE: &str = include_str!("../../../protocol/wire.txt");

    /// Every value this side defines, by its name in the table.
    fn ours() -> Vec<(&'static str, &'static str, u64)> {
        vec![
            ("handshake", "magic", MAGIC.into()),
            ("handshake", "version", VERSION.into()),
            ("handshake", "frame_len", FRAME_LEN as u64),
            ("handshake", "kind_hello", KIND_HELLO.into()),
            ("handshake", "kind_ack", KIND_ACK.into()),
            ("handshake", "kind_reject", KIND_REJECT.into()),
            ("handshake", "status_ok", STATUS_OK.into()),
            ("handshake", "status_bad_magic", STATUS_BAD_MAGIC.into()),
            ("handshake", "status_bad_version", STATUS_BAD_VERSION.into()),
            ("handshake", "status_bad_kind", STATUS_BAD_KIND.into()),
            ("shm", "slot_count", SLOT_COUNT.into()),
            ("shm", "slot_size", SLOT_SIZE as u64),
            ("shm", "slot_header", SLOT_HEADER as u64),
            ("shm", "payload_max", PAYLOAD_MAX as u64),
            ("shm", "shm_size", SHM_SIZE as u64),
            ("kind", "ping", MSG_PING.into()),
            ("kind", "pong", MSG_PONG.into()),
            ("kind", "md_identify", MSG_MD_IDENTIFY.into()),
            ("kind", "md_get", MSG_MD_GET.into()),
            ("kind", "md_set", MSG_MD_SET.into()),
            ("kind", "md_unset", MSG_MD_UNSET.into()),
            ("kind", "md_list", MSG_MD_LIST.into()),
            ("kind", "md_removed", MSG_MD_REMOVED.into()),
            ("kind", "md_moved", MSG_MD_MOVED.into()),
            ("kind", "health_query", MSG_HEALTH_QUERY.into()),
            ("kind", "health_subscribe", MSG_HEALTH_SUBSCRIBE.into()),
            ("kind", "op_start", MSG_OP_START.into()),
            ("kind", "op_cancel", MSG_OP_CANCEL.into()),
            ("kind", "reply", MSG_REPLY.into()),
            ("kind", "health_event", MSG_HEALTH_EVENT.into()),
            ("kind", "op_progress", MSG_OP_PROGRESS.into()),
            ("kind", "op_done", MSG_OP_DONE.into()),
            ("kind", "vfs_list", MSG_VFS_LIST.into()),
            ("kind", "vfs_delete", MSG_VFS_DELETE.into()),
            ("kind", "vfs_restore", MSG_VFS_RESTORE.into()),
            ("kind", "trash_empty", MSG_TRASH_EMPTY.into()),
            ("kind", "vfs_beat", MSG_VFS_BEAT.into()),
            ("kind", "vfs_stat", MSG_VFS_STAT.into()),
            ("kind", "vfs_children", MSG_VFS_CHILDREN.into()),
            ("kind", "vfs_stamp", MSG_VFS_STAMP.into()),
            ("status", "ok", ST_OK.into()),
            ("status", "not_found", ST_NOT_FOUND.into()),
            ("status", "busy", ST_BUSY.into()),
            ("status", "timeout", ST_TIMEOUT.into()),
            ("status", "suspect_mount", ST_SUSPECT_MOUNT.into()),
            ("status", "no_such_file", ST_NO_SUCH_FILE.into()),
            ("status", "bad_request", ST_BAD_REQUEST.into()),
            ("status", "key_too_long", ST_KEY_TOO_LONG.into()),
            ("status", "value_too_large", ST_VALUE_TOO_LARGE.into()),
            ("status", "too_many_keys", ST_TOO_MANY_KEYS.into()),
            ("status", "bad_utf8", ST_BAD_UTF8.into()),
            ("status", "io_error", ST_IO_ERROR.into()),
            ("status", "db_error", ST_DB_ERROR.into()),
            ("status", "unsupported", ST_UNSUPPORTED.into()),
            ("status", "cancelled", ST_CANCELLED.into()),
            ("status", "os_error", ST_OS_ERROR.into()),
            ("status", "would_recurse", ST_WOULD_RECURSE.into()),
            ("status", "mount_inside", ST_MOUNT_INSIDE.into()),
            ("status", "not_empty", ST_NOT_EMPTY.into()),
            ("scheme", "trash", SCHEME_TRASH.into()),
            ("scheme", "recent", SCHEME_RECENT.into()),
            ("item", "file", KIND_FILE.into()),
            ("item", "dir", KIND_DIR.into()),
            ("item", "symlink", KIND_SYMLINK.into()),
            ("item", "special", KIND_SPECIAL.into()),
        ]
    }

    type Values = Vec<(String, String, u64)>;
    type Frames = Vec<(String, Vec<u8>)>;

    /// `(group, name, value)` for each value line, and `(name, bytes)` for each frame.
    fn table() -> (Values, Frames) {
        let (mut values, mut frames) = (Vec::new(), Vec::new());
        for (n, line) in WIRE.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let f: Vec<&str> = line.split_whitespace().collect();
            assert_eq!(f.len(), 3, "wire.txt line {}: {line}", n + 1);
            if f[0] == "frame" {
                let bytes = (0..f[2].len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&f[2][i..i + 2], 16).expect("hex"))
                    .collect();
                frames.push((f[1].to_owned(), bytes));
                continue;
            }
            let v = match f[2].strip_prefix("0x") {
                Some(h) => u64::from_str_radix(h, 16),
                None => f[2].parse(),
            }
            .unwrap_or_else(|_| panic!("wire.txt line {}: bad value", n + 1));
            values.push((f[0].to_owned(), f[1].to_owned(), v));
        }
        (values, frames)
    }

    #[test]
    fn every_value_matches_the_shared_table() {
        let (file, _) = table();
        let ours = ours();
        for (g, n, v) in &ours {
            let theirs = file.iter().find(|(fg, fn_, _)| fg == g && fn_ == n);
            assert_eq!(
                theirs.map(|t| t.2),
                Some(*v),
                "{g} {n}: this side has {v}, protocol/wire.txt {theirs:?}"
            );
        }
        for (g, n, _) in &file {
            assert!(
                ours.iter().any(|(og, on, _)| og == g && on == n),
                "protocol/wire.txt has {g} {n}, which proto.rs lacks"
            );
        }
    }

    /// No two kinds share a number, and no two statuses do.
    #[test]
    fn kinds_and_statuses_are_distinct() {
        for group in ["kind", "status", "scheme", "item"] {
            let mut seen: Vec<u64> = ours()
                .into_iter()
                .filter(|(g, _, _)| *g == group)
                .map(|t| t.2)
                .collect();
            let n = seen.len();
            seen.sort_unstable();
            seen.dedup();
            assert_eq!(seen.len(), n, "a {group} number is used twice");
        }
    }

    #[test]
    fn frames_encode_as_the_shared_table_says() {
        let (_, frames) = table();
        let get = |name: &str| frames.iter().find(|f| f.0 == name).map(|f| f.1.clone());
        assert_eq!(
            Some(crate::ipc::Frame::hello().encode().to_vec()),
            get("hello")
        );
        let ack = crate::ipc::Frame {
            magic: MAGIC,
            version: VERSION,
            kind: KIND_ACK,
            status: STATUS_OK,
            shm_size: SHM_SIZE as u32,
        };
        assert_eq!(Some(ack.encode().to_vec()), get("ack"));
        assert_eq!(frames.len(), 2, "a frame here without a check");
    }

    #[test]
    fn the_envelope() {
        assert_eq!(reply_payload(ST_BUSY, b"xy"), [2, 0, 0, 0, b'x', b'y']);
        assert_eq!(os_error(-2), [15, 0, 0, 0, 0xfe, 0xff, 0xff, 0xff]);
    }
}
