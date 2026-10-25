//! Metadata protocol (protocol v2, milestone 5): the request and reply payloads that ride
//! in ring slots, their limits and validation, and a small blocking [`Client`] used by
//! the integration tests. Mirrored in `src/client-zig/src/md.zig`; keep both in sync.
//!
//! Every integer is little-endian. Building blocks:
//! - identity: `uuid_len u8 (1..=64) | fs_uuid | subvol u64 | inode u64 | generation u64 |
//!   btime_sec i64 | btime_nsec u32`
//! - key: `len u16 (1..=MAX_KEY_LEN) | UTF-8 bytes, no NUL`
//! - value: `type u8` then `1 string: len u16 | bytes` or
//!   `2 stringv: count u16 | count x (len u16 | bytes)`; strings are UTF-8 without NUL,
//!   the whole encoded value is at most [`MAX_VALUE_LEN`] bytes.
//!
//! Requests (client -> daemon, slot `kind`): identify `path bytes` | get `identity key` |
//! set `identity key value` | unset `identity key` | list `identity cursor-key` (the
//! cursor may be empty: keys strictly after it, in byte order) | removed `path bytes` |
//! moved `src path16 | dest path16` (milestone 6; a `path16` is `len u16 | bytes`). A
//! payload must be consumed exactly. Every request gets one [`MSG_MD_REPLY`] with the
//! request's `seq`: `status u32 | body`; bodies on [`ST_OK`]: identify -> identity, get ->
//! value, list -> `more u8 | count u16 | count x key`, set and unset -> empty, removed ->
//! `forgotten u32`, moved -> `rewritten u32 | forgotten u32`.
//!
//! removed and moved report a deletion or rename that already happened (GIO's
//! `local_file_removed` / `local_file_moved`). Metadata is keyed by identity, so a rename
//! keeps it; these only maintain `path_hint` and drop the rows of files that are gone.
//! They are new message kinds, not a layout change: protocol v2 stays, and an M5 daemon
//! answers them with [`ST_UNSUPPORTED`].

use std::{
    io::{self, Write},
    os::{fd::AsRawFd, unix::net::UnixStream},
    path::Path,
    time::{Duration, Instant},
};

use crate::{
    Error, Result,
    fsid::FileIdentity,
    ipc::{self, Frame, PAYLOAD_MAX, RING_C2D, RING_D2C, Shm},
};

pub const MSG_MD_IDENTIFY: u32 = 16;
pub const MSG_MD_GET: u32 = 17;
pub const MSG_MD_SET: u32 = 18;
pub const MSG_MD_UNSET: u32 = 19;
pub const MSG_MD_LIST: u32 = 20;
pub const MSG_MD_REMOVED: u32 = 21;
pub const MSG_MD_MOVED: u32 = 22;
pub const MSG_MD_REPLY: u32 = 32;

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

pub const MAX_UUID_LEN: usize = 64;
pub const MAX_KEY_LEN: usize = 256;
/// Encoded value (type byte and length prefixes included).
pub const MAX_VALUE_LEN: usize = 3072;
pub const MAX_STRINGV_ITEMS: usize = 64;
pub const MAX_KEYS_PER_FILE: usize = 128;

const VALUE_STRING: u8 = 1;
const VALUE_STRINGV: u8 = 2;
const IDENTITY_FIXED: usize = 1 + 8 + 8 + 8 + 8 + 4;

// A maximal set request must fit one slot.
const _: () = assert!(
    IDENTITY_FIXED + MAX_UUID_LEN + 2 + MAX_KEY_LEN + MAX_VALUE_LEN <= PAYLOAD_MAX,
    "a maximal set request does not fit one ring slot"
);

/// A protocol-level failure, mapped 1:1 to a reply status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MdError {
    NotFound,
    Busy,
    Timeout,
    SuspectMount,
    NoSuchFile,
    BadRequest,
    KeyTooLong,
    ValueTooLarge,
    TooManyKeys,
    BadUtf8,
    Io,
    Db,
    Unsupported,
}

impl MdError {
    #[must_use]
    pub fn status(self) -> u32 {
        match self {
            MdError::NotFound => ST_NOT_FOUND,
            MdError::Busy => ST_BUSY,
            MdError::Timeout => ST_TIMEOUT,
            MdError::SuspectMount => ST_SUSPECT_MOUNT,
            MdError::NoSuchFile => ST_NO_SUCH_FILE,
            MdError::BadRequest => ST_BAD_REQUEST,
            MdError::KeyTooLong => ST_KEY_TOO_LONG,
            MdError::ValueTooLarge => ST_VALUE_TOO_LARGE,
            MdError::TooManyKeys => ST_TOO_MANY_KEYS,
            MdError::BadUtf8 => ST_BAD_UTF8,
            MdError::Io => ST_IO_ERROR,
            MdError::Db => ST_DB_ERROR,
            MdError::Unsupported => ST_UNSUPPORTED,
        }
    }

    #[must_use]
    pub fn from_status(st: u32) -> Option<Self> {
        Some(match st {
            ST_NOT_FOUND => MdError::NotFound,
            ST_BUSY => MdError::Busy,
            ST_TIMEOUT => MdError::Timeout,
            ST_SUSPECT_MOUNT => MdError::SuspectMount,
            ST_NO_SUCH_FILE => MdError::NoSuchFile,
            ST_BAD_REQUEST => MdError::BadRequest,
            ST_KEY_TOO_LONG => MdError::KeyTooLong,
            ST_VALUE_TOO_LARGE => MdError::ValueTooLarge,
            ST_TOO_MANY_KEYS => MdError::TooManyKeys,
            ST_BAD_UTF8 => MdError::BadUtf8,
            ST_IO_ERROR => MdError::Io,
            ST_DB_ERROR => MdError::Db,
            ST_UNSUPPORTED => MdError::Unsupported,
            _ => return None,
        })
    }
}

impl std::fmt::Display for MdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for MdError {}

/// The metadata key of a file: the M4 identity without its diagnostics.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Ident {
    pub fs_uuid: String,
    pub subvol_id: u64,
    pub inode_num: u64,
    pub generation: u64,
    /// Staleness check only, not part of the key (AGENTS.md "btime").
    pub btime_sec: i64,
    pub btime_nsec: u32,
}

impl From<&FileIdentity> for Ident {
    fn from(f: &FileIdentity) -> Self {
        Self {
            fs_uuid: f.fs_uuid.clone(),
            subvol_id: f.subvol_id,
            inode_num: f.inode_num,
            generation: f.generation,
            btime_sec: f.btime_sec,
            btime_nsec: f.btime_nsec,
        }
    }
}

/// A metadata value: GIO's `string` and `stringv` attribute types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    String(String),
    Stringv(Vec<String>),
}

fn check_text(s: &[u8]) -> std::result::Result<&str, MdError> {
    let t = std::str::from_utf8(s).map_err(|_| MdError::BadUtf8)?;
    if t.as_bytes().contains(&0) {
        return Err(MdError::BadRequest);
    }
    Ok(t)
}

/// Validate a key: 1..=[`MAX_KEY_LEN`] bytes of UTF-8 without NUL.
///
/// # Errors
/// [`MdError::KeyTooLong`], [`MdError::BadUtf8`], [`MdError::BadRequest`] (empty or NUL).
pub fn check_key(k: &[u8]) -> std::result::Result<&str, MdError> {
    if k.is_empty() {
        return Err(MdError::BadRequest);
    }
    if k.len() > MAX_KEY_LEN {
        return Err(MdError::KeyTooLong);
    }
    check_text(k)
}

impl Value {
    /// Wire (and database) encoding, validated against the limits.
    ///
    /// # Errors
    /// [`MdError::ValueTooLarge`] or [`MdError::BadRequest`] (NUL inside a string).
    pub fn encode(&self) -> std::result::Result<Vec<u8>, MdError> {
        fn put(out: &mut Vec<u8>, s: &str) -> std::result::Result<(), MdError> {
            if s.as_bytes().contains(&0) {
                return Err(MdError::BadRequest);
            }
            let n = u16::try_from(s.len()).map_err(|_| MdError::ValueTooLarge)?;
            out.extend_from_slice(&n.to_le_bytes());
            out.extend_from_slice(s.as_bytes());
            Ok(())
        }
        let mut out = Vec::new();
        match self {
            Value::String(s) => {
                out.push(VALUE_STRING);
                put(&mut out, s)?;
            }
            Value::Stringv(v) => {
                if v.len() > MAX_STRINGV_ITEMS {
                    return Err(MdError::ValueTooLarge);
                }
                out.push(VALUE_STRINGV);
                out.extend_from_slice(&(v.len() as u16).to_le_bytes());
                for s in v {
                    put(&mut out, s)?;
                    if out.len() > MAX_VALUE_LEN {
                        return Err(MdError::ValueTooLarge);
                    }
                }
            }
        }
        if out.len() > MAX_VALUE_LEN {
            return Err(MdError::ValueTooLarge);
        }
        Ok(out)
    }

    /// Decode and validate an encoded value that must span `b` exactly.
    ///
    /// # Errors
    /// [`MdError::ValueTooLarge`], [`MdError::BadUtf8`] or [`MdError::BadRequest`].
    pub fn decode(b: &[u8]) -> std::result::Result<Self, MdError> {
        if b.len() > MAX_VALUE_LEN {
            return Err(MdError::ValueTooLarge);
        }
        let mut r = Reader(b);
        let v = match r.u8()? {
            VALUE_STRING => Value::String(check_text(r.blob16()?)?.to_owned()),
            VALUE_STRINGV => {
                let n = usize::from(r.u16()?);
                if n > MAX_STRINGV_ITEMS {
                    return Err(MdError::ValueTooLarge);
                }
                let mut v = Vec::with_capacity(n);
                for _ in 0..n {
                    v.push(check_text(r.blob16()?)?.to_owned());
                }
                Value::Stringv(v)
            }
            _ => return Err(MdError::BadRequest),
        };
        r.end()?;
        Ok(v)
    }
}

/// Bounds-checked reader over an untrusted payload: every short read is a
/// [`MdError::BadRequest`], never a panic.
pub struct Reader<'a>(pub &'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> std::result::Result<&'a [u8], MdError> {
        if self.0.len() < n {
            return Err(MdError::BadRequest);
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }

    fn arr<const N: usize>(&mut self) -> std::result::Result<[u8; N], MdError> {
        let s = self.take(N)?;
        let mut a = [0u8; N];
        a.copy_from_slice(s);
        Ok(a)
    }

    /// # Errors
    /// [`MdError::BadRequest`] if the payload is too short.
    pub fn u8(&mut self) -> std::result::Result<u8, MdError> {
        Ok(self.arr::<1>()?[0])
    }

    /// # Errors
    /// [`MdError::BadRequest`] if the payload is too short.
    pub fn u16(&mut self) -> std::result::Result<u16, MdError> {
        Ok(u16::from_le_bytes(self.arr()?))
    }

    /// # Errors
    /// [`MdError::BadRequest`] if the payload is too short.
    pub fn u32(&mut self) -> std::result::Result<u32, MdError> {
        Ok(u32::from_le_bytes(self.arr()?))
    }

    /// # Errors
    /// [`MdError::BadRequest`] if the payload is too short.
    pub fn u64(&mut self) -> std::result::Result<u64, MdError> {
        Ok(u64::from_le_bytes(self.arr()?))
    }

    /// `len u16 | bytes`.
    ///
    /// # Errors
    /// [`MdError::BadRequest`] if the payload is too short.
    pub fn blob16(&mut self) -> std::result::Result<&'a [u8], MdError> {
        let n = usize::from(self.u16()?);
        self.take(n)
    }

    /// The rest of the payload.
    #[must_use]
    pub fn rest(&mut self) -> &'a [u8] {
        std::mem::take(&mut self.0)
    }

    /// # Errors
    /// [`MdError::BadRequest`] if bytes are left over.
    pub fn end(&self) -> std::result::Result<(), MdError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(MdError::BadRequest)
        }
    }

    /// # Errors
    /// [`MdError::BadRequest`] for a malformed identity (empty, oversized or non-printable
    /// `fs_uuid`, short payload).
    pub fn ident(&mut self) -> std::result::Result<Ident, MdError> {
        let n = usize::from(self.u8()?);
        if n == 0 || n > MAX_UUID_LEN {
            return Err(MdError::BadRequest);
        }
        let raw = self.take(n)?;
        if !raw.iter().all(|b| b.is_ascii_graphic()) {
            return Err(MdError::BadRequest);
        }
        let fs_uuid = String::from_utf8(raw.to_vec()).map_err(|_| MdError::BadRequest)?;
        Ok(Ident {
            fs_uuid,
            subvol_id: self.u64()?,
            inode_num: self.u64()?,
            generation: self.u64()?,
            btime_sec: i64::from_le_bytes(self.arr()?),
            btime_nsec: self.u32()?,
        })
    }

    /// # Errors
    /// As [`check_key`], or [`MdError::BadRequest`] if the payload is too short.
    pub fn key(&mut self) -> std::result::Result<String, MdError> {
        Ok(check_key(self.blob16()?)?.to_owned())
    }
}

/// Append an identity.
///
/// # Errors
/// [`MdError::BadRequest`] if `fs_uuid` is empty, too long or not printable ASCII.
pub fn put_ident(out: &mut Vec<u8>, id: &Ident) -> std::result::Result<(), MdError> {
    let u = id.fs_uuid.as_bytes();
    if u.is_empty() || u.len() > MAX_UUID_LEN || !u.iter().all(u8::is_ascii_graphic) {
        return Err(MdError::BadRequest);
    }
    out.push(u.len() as u8);
    out.extend_from_slice(u);
    out.extend_from_slice(&id.subvol_id.to_le_bytes());
    out.extend_from_slice(&id.inode_num.to_le_bytes());
    out.extend_from_slice(&id.generation.to_le_bytes());
    out.extend_from_slice(&id.btime_sec.to_le_bytes());
    out.extend_from_slice(&id.btime_nsec.to_le_bytes());
    Ok(())
}

/// Append a key (length-prefixed). An empty `key` is allowed here: it is the list cursor
/// "from the start".
///
/// # Errors
/// [`MdError::KeyTooLong`].
pub fn put_key(out: &mut Vec<u8>, key: &str) -> std::result::Result<(), MdError> {
    if key.len() > MAX_KEY_LEN {
        return Err(MdError::KeyTooLong);
    }
    out.extend_from_slice(&(key.len() as u16).to_le_bytes());
    out.extend_from_slice(key.as_bytes());
    Ok(())
}

/// A parsed, validated request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    Identify(Vec<u8>),
    Get(Ident, String),
    Set(Ident, String, Value),
    Unset(Ident, String),
    /// Keys strictly after the cursor (empty: from the start).
    List(Ident, String),
    /// The file at this path was deleted.
    Removed(Vec<u8>),
    /// The file at `src` was renamed to `dest`.
    Moved(Vec<u8>, Vec<u8>),
}

/// An absolute path without NUL.
fn check_path(p: &[u8]) -> std::result::Result<(), MdError> {
    if p.first() != Some(&b'/') || p.contains(&0) {
        return Err(MdError::BadRequest);
    }
    Ok(())
}

impl Request {
    /// Parse one request slot.
    ///
    /// # Errors
    /// The status to reply with; [`MdError::Unsupported`] for an unknown `kind`.
    pub fn parse(kind: u32, payload: &[u8]) -> std::result::Result<Self, MdError> {
        let mut r = Reader(payload);
        let req = match kind {
            MSG_MD_IDENTIFY | MSG_MD_REMOVED => {
                let p = r.rest();
                check_path(p)?;
                if kind == MSG_MD_IDENTIFY {
                    Request::Identify(p.to_vec())
                } else {
                    Request::Removed(p.to_vec())
                }
            }
            MSG_MD_MOVED => {
                let src = r.blob16()?;
                let dest = r.blob16()?;
                check_path(src)?;
                check_path(dest)?;
                if src == dest {
                    return Err(MdError::BadRequest);
                }
                Request::Moved(src.to_vec(), dest.to_vec())
            }
            MSG_MD_GET => Request::Get(r.ident()?, r.key()?),
            MSG_MD_SET => {
                let id = r.ident()?;
                let key = r.key()?;
                let v = Value::decode(r.rest())?;
                Request::Set(id, key, v)
            }
            MSG_MD_UNSET => Request::Unset(r.ident()?, r.key()?),
            MSG_MD_LIST => {
                let id = r.ident()?;
                let cursor = r.blob16()?;
                let cursor = if cursor.is_empty() {
                    String::new()
                } else {
                    check_key(cursor)?.to_owned()
                };
                Request::List(id, cursor)
            }
            _ => return Err(MdError::Unsupported),
        };
        r.end()?;
        Ok(req)
    }

    /// Encode as `(kind, payload)`.
    ///
    /// # Errors
    /// Limit violations ([`MdError::KeyTooLong`], [`MdError::ValueTooLarge`], ...).
    pub fn encode(&self) -> std::result::Result<(u32, Vec<u8>), MdError> {
        let mut out = Vec::new();
        let kind = match self {
            Request::Identify(p) => {
                if p.len() > PAYLOAD_MAX {
                    return Err(MdError::BadRequest);
                }
                out.extend_from_slice(p);
                MSG_MD_IDENTIFY
            }
            Request::Get(id, k) => {
                put_ident(&mut out, id)?;
                put_key(&mut out, k)?;
                MSG_MD_GET
            }
            Request::Set(id, k, v) => {
                put_ident(&mut out, id)?;
                put_key(&mut out, k)?;
                out.extend_from_slice(&v.encode()?);
                MSG_MD_SET
            }
            Request::Unset(id, k) => {
                put_ident(&mut out, id)?;
                put_key(&mut out, k)?;
                MSG_MD_UNSET
            }
            Request::List(id, cursor) => {
                put_ident(&mut out, id)?;
                put_key(&mut out, cursor)?;
                MSG_MD_LIST
            }
            Request::Removed(p) => {
                if p.len() > PAYLOAD_MAX {
                    return Err(MdError::BadRequest);
                }
                out.extend_from_slice(p);
                MSG_MD_REMOVED
            }
            Request::Moved(src, dest) => {
                if 4 + src.len() + dest.len() > PAYLOAD_MAX {
                    return Err(MdError::BadRequest);
                }
                for p in [src, dest] {
                    out.extend_from_slice(&(p.len() as u16).to_le_bytes());
                    out.extend_from_slice(p);
                }
                MSG_MD_MOVED
            }
        };
        Ok((kind, out))
    }
}

/// Reply payload: `status u32 | body`.
#[must_use]
pub fn reply_payload(status: u32, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&status.to_le_bytes());
    out.extend_from_slice(body);
    out
}

/// List reply body for `keys` (ascending): as many as fit `PAYLOAD_MAX - 4`, `more` set
/// if some did not.
#[must_use]
pub fn list_body(keys: &[String], more_in_db: bool) -> Vec<u8> {
    let mut out = vec![0u8, 0, 0];
    let mut n: u16 = 0;
    let mut more = more_in_db;
    for k in keys {
        if out.len() + 2 + k.len() > PAYLOAD_MAX - 4 {
            more = true;
            break;
        }
        out.extend_from_slice(&(k.len() as u16).to_le_bytes());
        out.extend_from_slice(k.as_bytes());
        n += 1;
    }
    out[0] = u8::from(more);
    out[1..3].copy_from_slice(&n.to_le_bytes());
    out
}

/// Split a reply payload into the body ([`ST_OK`]) or the status.
///
/// # Errors
/// [`ClientError::Status`], or [`ClientError::Transport`] for a malformed reply.
pub fn reply_result(payload: &[u8]) -> ClientResult<Vec<u8>> {
    let mut r = Reader(payload);
    let st = r.u32().map_err(|_| Error::Protocol("short reply"))?;
    if st == ST_OK {
        return Ok(r.rest().to_vec());
    }
    Err(MdError::from_status(st).map_or(
        Error::Protocol("unknown status").into(),
        ClientError::Status,
    ))
}

// ---------------------------------------------------------------------------------------
// Blocking client (tests and diagnostics; the GIO module has its own in Zig)

/// A connected protocol-v2 client: control socket plus the mapped ring pair. One
/// request at a time; every wait is bounded by `timeout`.
pub struct Client {
    _sock: UnixStream,
    shm: Shm,
    seq: u64,
    pub timeout: Duration,
}

/// What a request returned: the daemon's status, or a transport failure.
#[derive(Debug)]
pub enum ClientError {
    Status(MdError),
    Transport(Error),
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::Status(e) => write!(f, "daemon answered {e}"),
            ClientError::Transport(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<Error> for ClientError {
    fn from(e: Error) -> Self {
        ClientError::Transport(e)
    }
}

impl From<MdError> for ClientError {
    fn from(e: MdError) -> Self {
        ClientError::Status(e)
    }
}

impl From<io::Error> for ClientError {
    fn from(e: io::Error) -> Self {
        ClientError::Transport(Error::Io(e))
    }
}

pub type ClientResult<T> = std::result::Result<T, ClientError>;

impl Client {
    /// Connect to the daemon at `sock` and complete the hello.
    ///
    /// # Errors
    /// I/O errors, [`Error::Protocol`] for a rejected or malformed handshake.
    pub fn connect(sock: &Path, timeout: Duration) -> Result<Self> {
        let mut s = UnixStream::connect(sock)?;
        if ipc::peer_uid(&s)? != unsafe { libc::geteuid() } {
            return Err(Error::Protocol("daemon runs as another user"));
        }
        s.set_read_timeout(Some(timeout))?;
        s.set_write_timeout(Some(timeout))?;
        s.write_all(&Frame::hello().encode())?;
        let (reply, fd) = ipc::recv_with_fd(&s)?;
        if reply.kind != ipc::KIND_ACK || reply.status != ipc::STATUS_OK {
            return Err(Error::Protocol("hello rejected"));
        }
        let fd = fd.ok_or(Error::Protocol("ack without a memfd"))?;
        let shm = Shm::map(fd.as_raw_fd())?;
        Ok(Self {
            _sock: s,
            shm,
            seq: 0,
            timeout,
        })
    }

    /// Send one request and wait for its reply; returns the body on [`ST_OK`].
    ///
    /// # Errors
    /// [`ClientError::Status`] for a non-OK status, [`ClientError::Transport`] otherwise.
    pub fn call(&mut self, req: &Request) -> ClientResult<Vec<u8>> {
        let (kind, payload) = req.encode()?;
        self.raw_call(kind, &payload)
    }

    /// Send a raw slot (any kind, any payload) and wait for its reply.
    ///
    /// # Errors
    /// As [`Client::call`].
    pub fn raw_call(&mut self, kind: u32, payload: &[u8]) -> ClientResult<Vec<u8>> {
        let seq = self.send(kind, payload)?;
        let deadline = Instant::now() + self.timeout;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let m = self.recv(left)?;
            if m.seq != seq {
                continue; // a late reply to an earlier, timed-out request
            }
            if m.kind != MSG_MD_REPLY {
                return Err(Error::Protocol("unexpected reply kind").into());
            }
            return reply_result(m.payload());
        }
    }

    /// Send a ping frame and wait for its matching pong.
    ///
    /// # Errors
    /// [`Error::Protocol`] on timeout or unexpected reply.
    pub fn ping(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        let seq = self.send(ipc::MSG_PING, payload)?;
        let deadline = Instant::now() + self.timeout;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let m = self.recv(left)?;
            if m.seq != seq {
                continue;
            }
            if m.kind != ipc::MSG_PONG {
                return Err(Error::Protocol("expected pong reply"));
            }
            return Ok(m.payload().to_vec());
        }
    }

    /// Push one request without waiting; returns its `seq`.
    ///
    /// # Errors
    /// [`Error::RingFull`] or [`Error::Protocol`].
    pub fn send(&mut self, kind: u32, payload: &[u8]) -> Result<u64> {
        self.seq += 1;
        self.shm.push(RING_C2D, kind, self.seq, payload)?;
        Ok(self.seq)
    }

    /// The next message from the daemon, waiting at most `timeout`.
    ///
    /// # Errors
    /// [`Error::Protocol`] on timeout or a corrupt ring.
    pub fn recv(&mut self, timeout: Duration) -> Result<ipc::Msg> {
        if let Some(m) = self.shm.pop(RING_D2C)? {
            return Ok(m);
        }
        if !self.shm.wait_readable(RING_D2C, timeout) {
            return Err(Error::Protocol("reply timed out"));
        }
        self.shm
            .pop(RING_D2C)?
            .ok_or(Error::Protocol("ring emptied"))
    }

    /// # Errors
    /// As [`Client::call`].
    pub fn identify(&mut self, path: &Path) -> ClientResult<Ident> {
        use std::os::unix::ffi::OsStrExt;
        let body = self.call(&Request::Identify(path.as_os_str().as_bytes().to_vec()))?;
        let mut r = Reader(&body);
        let id = r.ident()?;
        r.end()?;
        Ok(id)
    }

    /// `Ok(None)` if the key is not set.
    ///
    /// # Errors
    /// As [`Client::call`].
    pub fn get(&mut self, id: &Ident, key: &str) -> ClientResult<Option<Value>> {
        match self.call(&Request::Get(id.clone(), key.to_owned())) {
            Ok(b) => Ok(Some(Value::decode(&b)?)),
            Err(ClientError::Status(MdError::NotFound)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// # Errors
    /// As [`Client::call`].
    pub fn set(&mut self, id: &Ident, key: &str, v: &Value) -> ClientResult<()> {
        self.call(&Request::Set(id.clone(), key.to_owned(), v.clone()))
            .map(drop)
    }

    /// # Errors
    /// As [`Client::call`].
    pub fn unset(&mut self, id: &Ident, key: &str) -> ClientResult<()> {
        self.call(&Request::Unset(id.clone(), key.to_owned()))
            .map(drop)
    }

    /// Report a deleted file; returns how many identities' metadata was dropped.
    ///
    /// # Errors
    /// As [`Client::call`].
    pub fn removed(&mut self, path: &Path) -> ClientResult<u32> {
        use std::os::unix::ffi::OsStrExt;
        let body = self.call(&Request::Removed(path.as_os_str().as_bytes().to_vec()))?;
        let mut r = Reader(&body);
        let n = r.u32()?;
        r.end()?;
        Ok(n)
    }

    /// Report a rename; returns `(path hints rewritten, identities dropped)`.
    ///
    /// # Errors
    /// As [`Client::call`].
    pub fn moved(&mut self, src: &Path, dest: &Path) -> ClientResult<(u32, u32)> {
        use std::os::unix::ffi::OsStrExt;
        let body = self.call(&Request::Moved(
            src.as_os_str().as_bytes().to_vec(),
            dest.as_os_str().as_bytes().to_vec(),
        ))?;
        let mut r = Reader(&body);
        let v = (r.u32()?, r.u32()?);
        r.end()?;
        Ok(v)
    }

    /// Every key of the file, following the pagination.
    ///
    /// # Errors
    /// As [`Client::call`].
    pub fn list(&mut self, id: &Ident) -> ClientResult<Vec<String>> {
        let mut keys: Vec<String> = Vec::new();
        loop {
            let cursor = keys.last().cloned().unwrap_or_default();
            let body = self.call(&Request::List(id.clone(), cursor))?;
            let mut r = Reader(&body);
            let more = r.u8()? != 0;
            let n = r.u16()?;
            for _ in 0..n {
                keys.push(r.key()?);
            }
            r.end()?;
            if !more {
                return Ok(keys);
            }
            if n == 0 {
                return Err(Error::Protocol("list made no progress").into());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id() -> Ident {
        Ident {
            fs_uuid: "0123abcd-0000-4000-8000-00000000beef".into(),
            subvol_id: 5,
            inode_num: u64::MAX,
            generation: 7,
            btime_sec: -3,
            btime_nsec: 999,
        }
    }

    #[test]
    fn requests_round_trip() -> std::result::Result<(), MdError> {
        let reqs = [
            Request::Identify(b"/a/b".to_vec()),
            Request::Get(id(), "k".into()),
            Request::Set(id(), "k".into(), Value::String("v\u{e9}".into())),
            Request::Set(
                id(),
                "x".repeat(MAX_KEY_LEN),
                Value::Stringv(vec!["a".into(), String::new(), "c".into()]),
            ),
            Request::Unset(id(), "k".into()),
            Request::List(id(), String::new()),
            Request::List(id(), "after".into()),
            Request::Removed(b"/gone".to_vec()),
            Request::Moved(b"/a/old".to_vec(), b"/b/new".to_vec()),
        ];
        for r in reqs {
            let (kind, p) = r.encode()?;
            assert_eq!(Request::parse(kind, &p)?, r);
        }
        Ok(())
    }

    #[test]
    fn limits_and_validation() -> std::result::Result<(), MdError> {
        assert_eq!(
            check_key(&[b'k'; MAX_KEY_LEN + 1]),
            Err(MdError::KeyTooLong)
        );
        assert_eq!(check_key(b""), Err(MdError::BadRequest));
        assert_eq!(check_key(b"a\0b"), Err(MdError::BadRequest));
        assert_eq!(check_key(&[0xff, 0xfe]), Err(MdError::BadUtf8));
        let big = Value::String("v".repeat(MAX_VALUE_LEN));
        assert_eq!(big.encode(), Err(MdError::ValueTooLarge));
        let many = Value::Stringv(vec![String::new(); MAX_STRINGV_ITEMS + 1]);
        assert_eq!(many.encode(), Err(MdError::ValueTooLarge));
        let fits = Value::String("v".repeat(MAX_VALUE_LEN - 3));
        assert_eq!(Value::decode(&fits.encode()?)?, fits);
        // Non-UTF-8 inside a value, built by hand.
        assert_eq!(Value::decode(&[1, 2, 0, 0xc3, 0x28]), Err(MdError::BadUtf8));
        // Trailing bytes, short reads, unknown types, unknown kinds.
        assert_eq!(
            Value::decode(&[1, 1, 0, b'a', b'b']),
            Err(MdError::BadRequest)
        );
        assert_eq!(Value::decode(&[1, 9, 0, b'a']), Err(MdError::BadRequest));
        assert_eq!(Value::decode(&[3]), Err(MdError::BadRequest));
        assert_eq!(Request::parse(99, b""), Err(MdError::Unsupported));
        assert_eq!(
            Request::parse(MSG_MD_IDENTIFY, b"relative"),
            Err(MdError::BadRequest)
        );
        assert_eq!(
            Request::parse(MSG_MD_REMOVED, b"/a\0b"),
            Err(MdError::BadRequest)
        );
        let moved = |s: &[u8], d: &[u8]| {
            Request::Moved(s.to_vec(), d.to_vec())
                .encode()
                .map(|(k, p)| Request::parse(k, &p))
        };
        assert_eq!(moved(b"/same", b"/same")?, Err(MdError::BadRequest));
        assert_eq!(moved(b"rel", b"/d")?, Err(MdError::BadRequest));
        assert_eq!(moved(b"/s", b"")?, Err(MdError::BadRequest));
        assert_eq!(
            Request::Moved(vec![b'/'; PAYLOAD_MAX / 2], vec![b'/'; PAYLOAD_MAX / 2]).encode(),
            Err(MdError::BadRequest)
        );
        let (k, mut p) = Request::Get(id(), "k".into()).encode()?;
        p.push(0);
        assert_eq!(Request::parse(k, &p), Err(MdError::BadRequest));
        let mut bad = id();
        bad.fs_uuid = "has space".into();
        assert_eq!(
            Request::Get(bad, "k".into()).encode(),
            Err(MdError::BadRequest)
        );
        Ok(())
    }

    #[test]
    fn every_truncation_is_an_error_not_a_panic() -> std::result::Result<(), MdError> {
        let (kind, p) = Request::Set(
            id(),
            "key".into(),
            Value::Stringv(vec!["one".into(), "two".into()]),
        )
        .encode()?;
        for n in 0..p.len() {
            assert!(Request::parse(kind, &p[..n]).is_err(), "prefix {n}");
        }
        let (kind, p) = Request::Moved(b"/a".to_vec(), b"/b/c".to_vec()).encode()?;
        for n in 0..p.len() {
            assert!(Request::parse(kind, &p[..n]).is_err(), "moved prefix {n}");
        }
        Ok(())
    }

    #[test]
    fn list_body_paginates() {
        let keys: Vec<String> = (0..MAX_KEYS_PER_FILE)
            .map(|i| format!("{i:03}{}", "k".repeat(MAX_KEY_LEN - 3)))
            .collect();
        let b = list_body(&keys, false);
        assert!(b.len() <= PAYLOAD_MAX - 4);
        assert_eq!(b[0], 1);
        let n = u16::from_le_bytes([b[1], b[2]]) as usize;
        assert!(n > 0 && n < keys.len());
        let small = list_body(&keys[..2], false);
        assert_eq!((small[0], small[1]), (0, 2));
    }

    #[test]
    fn statuses_map_both_ways() {
        for st in ST_NOT_FOUND..=ST_UNSUPPORTED {
            assert_eq!(MdError::from_status(st).map(MdError::status), Some(st));
        }
        assert_eq!(MdError::from_status(ST_OK), None);
        assert_eq!(MdError::from_status(1000), None);
    }
}
