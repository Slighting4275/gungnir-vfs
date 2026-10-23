//! The metadata service on the ring (milestone 5): parses requests on the connection's
//! ring thread, identifies paths through the M4 [`Resolver`] (bounded by its deadline),
//! and hands every database operation to the database thread ([`crate::store`]) without
//! waiting for it; the database thread pushes the reply itself.

use std::{
    collections::HashMap, ffi::OsStr, io, os::unix::ffi::OsStrExt, path::PathBuf, sync::Arc,
    time::Instant,
};

use crate::{
    fsid::{Backend, FsidError, Resolver, Target},
    ipc::{Handler, Msg, Port, Session},
    md::{Ident, MSG_MD_REPLY, MdError, Request, ST_OK, put_ident, reply_payload},
    store::{DbHandle, DbReq, Job},
};

/// Paths remembered per connection (identity -> path of its last identify), so a later
/// set can record the file's last known path. Cleared when full: it is only a hint.
pub const HINT_CACHE: usize = 256;

pub struct Service<B: Backend> {
    resolver: Arc<Resolver<B>>,
    db: DbHandle,
}

impl<B: Backend> Service<B> {
    #[must_use]
    pub fn new(resolver: Arc<Resolver<B>>, db: DbHandle) -> Self {
        Self { resolver, db }
    }
}

impl<B: Backend> Handler for Service<B> {
    fn session(&self) -> Box<dyn Session> {
        Box::new(MdSession {
            resolver: Arc::clone(&self.resolver),
            db: self.db.clone(),
            hints: HashMap::new(),
        })
    }
}

struct MdSession<B: Backend> {
    resolver: Arc<Resolver<B>>,
    db: DbHandle,
    hints: HashMap<Ident, (Vec<u8>, u32)>,
}

/// Map an identity lookup failure to a reply status.
#[must_use]
pub fn fsid_status(e: &FsidError) -> MdError {
    match e {
        FsidError::Timeout(_) => MdError::Timeout,
        FsidError::SuspectMount(_) => MdError::SuspectMount,
        FsidError::Busy | FsidError::Shutdown => MdError::Busy,
        FsidError::NotAbsolute(_) => MdError::BadRequest,
        FsidError::Io(io) => match io.raw_os_error() {
            Some(libc::ENOENT | libc::ENOTDIR | libc::ELOOP) => MdError::NoSuchFile,
            Some(libc::ENAMETOOLONG) => MdError::BadRequest,
            _ if io.kind() == io::ErrorKind::NotFound => MdError::NoSuchFile,
            _ => MdError::Io,
        },
        FsidError::UnknownMount { .. } | FsidError::NoBootId => MdError::Io,
        // btrfs without STATX_SUBVOL and a file that cannot be opened for the subvolume
        // ioctl: no reliable key, so no metadata for it (never subvolume 0).
        FsidError::NoSubvol => MdError::Unsupported,
    }
}

/// Hint key: the identity without btime (a stale btime must not split the cache).
fn hint_key(id: &Ident) -> Ident {
    Ident {
        btime_sec: 0,
        btime_nsec: 0,
        ..id.clone()
    }
}

impl<B: Backend> MdSession<B> {
    /// Identify `path` through the resolver (bounded by its deadline): the identity and
    /// the file's hard link count.
    fn resolve(&self, path: &[u8]) -> Result<(Ident, u32), MdError> {
        let fi = self
            .resolver
            .resolve(Target::Path(PathBuf::from(OsStr::from_bytes(path))))
            .map_err(|e| fsid_status(&e))?;
        Ok((Ident::from(&fi), fi.nlink))
    }

    fn identify(&mut self, path: Vec<u8>) -> Result<Vec<u8>, MdError> {
        let (id, nlink) = self.resolve(&path)?;
        // The one place the daemon knows the file's current btime: rows of an earlier file
        // on this inode are dropped here (queued ahead of every later request of this
        // connection), never on the btime a client sends with get/set.
        if (id.btime_sec, id.btime_nsec) != (0, 0) {
            self.db.submit(Job {
                req: DbReq::Purge(id.clone()),
                enqueued: Instant::now(),
                done: Box::new(|_| {}),
            })?;
        }
        let mut body = Vec::new();
        put_ident(&mut body, &id).map_err(|_| MdError::Io)?;
        if self.hints.len() >= HINT_CACHE {
            self.hints.clear();
        }
        self.hints.insert(hint_key(&id), (path, nlink));
        Ok(body)
    }

    fn db_req(&self, req: Request) -> Result<DbReq, MdError> {
        Ok(match req {
            Request::Get(id, k) => DbReq::Get(id, k),
            Request::Set(id, k, v) => {
                let hint = self.hints.get(&hint_key(&id)).cloned();
                DbReq::Set(id, k, v.encode()?, hint)
            }
            Request::Unset(id, k) => DbReq::Unset(id, k),
            Request::List(id, cursor) => DbReq::List(id, cursor),
            // What is at the deleted path now: nothing (the usual case), or a file that
            // must keep its metadata. Any other failure (a hung mount) drops nothing.
            Request::Removed(path) => {
                let alive = match self.resolve(&path) {
                    Ok((id, _)) => Some(id),
                    Err(MdError::NoSuchFile) => None,
                    Err(e) => return Err(e),
                };
                DbReq::Removed(path, alive)
            }
            Request::Moved(src, dest) => {
                let (id, _) = self.resolve(&dest)?;
                DbReq::Moved(src, dest, id)
            }
            Request::Identify(_) => return Err(MdError::BadRequest),
        })
    }
}

fn answer(port: &Port, seq: u64, r: Result<Vec<u8>, MdError>) {
    match r {
        Ok(body) => port.reply(MSG_MD_REPLY, seq, &reply_payload(ST_OK, &body)),
        Err(e) => port.reply(MSG_MD_REPLY, seq, &reply_payload(e.status(), &[])),
    }
}

impl<B: Backend> Session for MdSession<B> {
    fn request(&mut self, port: &Arc<Port>, msg: &Msg) {
        let seq = msg.seq;
        let req = match Request::parse(msg.kind, msg.payload()) {
            Ok(Request::Identify(path)) => return answer(port, seq, self.identify(path)),
            Ok(r) => self.db_req(r),
            Err(e) => Err(e),
        };
        let req = match req {
            Ok(r) => r,
            Err(e) => return answer(port, seq, Err(e)),
        };
        let guard = port.begin();
        let job = Job {
            req,
            enqueued: Instant::now(),
            done: Box::new(move |r| answer(guard.port(), seq, r)),
        };
        // A refused job is dropped with its in-flight guard; answer here instead.
        if let Err(e) = self.db.submit(job) {
            answer(port, seq, Err(e));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_errors_map_to_statuses() {
        let io = |n| FsidError::Io(io::Error::from_raw_os_error(n));
        assert_eq!(fsid_status(&io(libc::ENOENT)), MdError::NoSuchFile);
        assert_eq!(fsid_status(&io(libc::EACCES)), MdError::Io);
        assert_eq!(fsid_status(&FsidError::Busy), MdError::Busy);
        assert_eq!(
            fsid_status(&FsidError::Timeout(std::time::Duration::ZERO)),
            MdError::Timeout
        );
        assert_eq!(
            fsid_status(&FsidError::SuspectMount(PathBuf::from("/m"))),
            MdError::SuspectMount
        );
        assert_eq!(fsid_status(&FsidError::NoSubvol), MdError::Unsupported);
    }
}
