//! File operations on the ring (milestone 8): serves [`MSG_OP_START`] and
//! [`MSG_OP_CANCEL`] for one connection and hands everything else to the inner session;
//! wires [`Ops`] to the M7 health monitor (the gate) and to the M5/M6 metadata store (so
//! metadata follows moved and copied files). See [`crate::ops`] for the protocol.

use std::{
    ffi::OsStr,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, PoisonError, Weak, mpsc},
    time::{Duration, Instant},
};

use crate::{
    fsid::{Backend, Resolver, Target},
    health::{EVENT_RESERVE, Monitor},
    ipc::{Handler, Msg, Port, Session},
    md::{Ident, MSG_MD_REPLY, ST_BAD_REQUEST, ST_BUSY, ST_NOT_FOUND, ST_OK, reply_payload},
    ops::{
        Done, Gate, MSG_OP_CANCEL, MSG_OP_DONE, MSG_OP_PROGRESS, MSG_OP_START, MetaHooks, OpCtl,
        OpRequest, Ops, Progress, Sink, done_payload, progress_payload,
    },
    store::{DbHandle, DbReq, Job},
};

/// The M7 monitor as the ops' health gate (lexical lookups only).
pub struct MonitorGate(Arc<Monitor>);

impl MonitorGate {
    #[must_use]
    pub fn new(m: Arc<Monitor>) -> Self {
        Self(m)
    }
}

impl Gate for MonitorGate {
    fn blocking(&self, path: &[u8]) -> Option<PathBuf> {
        self.0
            .blocking_mount(Path::new(OsStr::from_bytes(path)))
            .map(|h| h.mount_point)
    }

    fn mount_of(&self, path: &[u8]) -> Option<PathBuf> {
        self.0.lookup(path).map(|r| r.hint.mount_point)
    }
}

/// Metadata follows the files: identities through the M4 resolver (its deadline and the
/// health gate apply), rows through the database thread. Each call waits at most `wait`
/// for the database, so an op's done event comes after its metadata moved (or after
/// that wait, best effort).
pub struct DbMeta<B: Backend> {
    resolver: Arc<Resolver<B>>,
    db: DbHandle,
    wait: Duration,
}

impl<B: Backend> DbMeta<B> {
    #[must_use]
    pub fn new(resolver: Arc<Resolver<B>>, db: DbHandle) -> Self {
        Self {
            resolver,
            db,
            wait: Duration::from_secs(1),
        }
    }

    fn run(&self, req: DbReq) {
        let (tx, rx) = mpsc::sync_channel(1);
        let job = Job {
            req,
            enqueued: Instant::now(),
            done: Box::new(move |r| {
                let _ = tx.try_send(r);
            }),
        };
        if let Err(e) = self.db.submit(job) {
            eprintln!("gungnird: file op metadata update dropped: {e}");
            return;
        }
        match rx.recv_timeout(self.wait) {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => eprintln!("gungnird: file op metadata update failed: {e}"),
            Err(_) => eprintln!("gungnird: file op metadata update still queued"),
        }
    }
}

impl<B: Backend> MetaHooks for DbMeta<B> {
    fn identify(&self, path: &[u8]) -> Option<Ident> {
        self.resolver
            .resolve(Target::Path(PathBuf::from(OsStr::from_bytes(path))))
            .ok()
            .map(|f| Ident::from(&f))
    }

    fn moved(&self, src: &[u8], dest: &[u8]) {
        if let Some(id) = self.identify(dest) {
            self.run(DbReq::Moved(src.to_vec(), dest.to_vec(), id));
        }
    }

    fn copied(&self, from: &Ident, dest: &[u8], forget_src: bool) {
        // The copy cannot be identified (gone again, or its mount turned hung): its
        // metadata is lost, as with any copy GIO makes without the daemon.
        if let Some(to) = self.identify(dest) {
            self.run(DbReq::Copied(from.clone(), to, dest.to_vec(), forget_src));
        }
    }

    fn removed_paths(&self, paths: &[(Vec<u8>, bool)]) {
        self.run(DbReq::RemovedPaths(paths.to_vec()));
    }

    fn removed(&self, path: &[u8], tree: bool) {
        if tree {
            self.run(DbReq::RemovedTree(path.to_vec()));
        } else {
            self.run(DbReq::Removed(path.to_vec(), None));
        }
    }
}

/// Delivers one op's events to its connection. Held back until the start request's
/// reply (with the op id) is on the ring, so a fast op can never overtake it.
struct PortSink {
    port: Weak<Port>,
    seq: u64,
    reserve: usize,
    state: Mutex<SinkState>,
}

#[derive(Default)]
struct SinkState {
    open: bool,
    done: Option<Vec<u8>>,
}

impl PortSink {
    fn open(&self) {
        let mut s = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        s.open = true;
        if let (Some(d), Some(p)) = (s.done.take(), self.port.upgrade()) {
            p.reply(MSG_OP_DONE, self.seq, &d);
        }
    }
}

impl Sink for PortSink {
    fn progress(&self, id: u64, pr: &Progress) {
        let s = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if !s.open {
            return;
        }
        if let Some(p) = self.port.upgrade() {
            // Dropped when the ring is busy: the next one (or the done) supersedes it.
            p.push_unsolicited(MSG_OP_PROGRESS, &[progress_payload(id, pr)], self.reserve);
        }
    }

    fn done(&self, d: &Done) {
        let payload = done_payload(d);
        let mut s = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if !s.open {
            s.done = Some(payload);
            return;
        }
        if let Some(p) = self.port.upgrade() {
            // Room is kept for it: progress events leave `reserve` slots free.
            p.reply(MSG_OP_DONE, self.seq, &payload);
        }
    }
}

/// Serves the file-op requests and hands everything else to `inner`.
pub struct OpsHandler {
    inner: Arc<dyn Handler>,
    ops: Arc<Ops>,
}

impl OpsHandler {
    pub fn new(inner: Arc<dyn Handler>, ops: Arc<Ops>) -> Self {
        Self { inner, ops }
    }
}

impl Handler for OpsHandler {
    fn session(&self) -> Box<dyn Session> {
        Box::new(OpsSession {
            inner: self.inner.session(),
            ops: Arc::clone(&self.ops),
            active: Vec::new(),
        })
    }
}

struct OpsSession {
    inner: Box<dyn Session>,
    ops: Arc<Ops>,
    active: Vec<Arc<OpCtl>>,
}

impl OpsSession {
    fn start(&mut self, port: &Arc<Port>, msg: &Msg) {
        let reply =
            |st: u32, body: &[u8]| port.reply(MSG_MD_REPLY, msg.seq, &reply_payload(st, body));
        let req = match OpRequest::parse(msg.payload()) {
            Ok(r) => r,
            Err(e) => return reply(e.status().0, &[]),
        };
        self.active.retain(|op| !op.is_finished());
        let per_conn = self.ops.config().per_conn;
        if self.active.len() >= per_conn.max(1) {
            return reply(ST_BUSY, &[]);
        }
        let sink = Arc::new(PortSink {
            port: Arc::downgrade(port),
            seq: msg.seq,
            reserve: EVENT_RESERVE + per_conn,
            state: Mutex::new(SinkState::default()),
        });
        match self.ops.submit(req, sink.clone()) {
            Ok(ctl) => {
                reply(ST_OK, &ctl.id.to_le_bytes());
                sink.open();
                self.active.push(ctl);
            }
            Err(e) => reply(e.status().0, &[]),
        }
    }

    fn cancel(&mut self, port: &Arc<Port>, msg: &Msg) {
        let st = match <[u8; 8]>::try_from(msg.payload()) {
            Err(_) => ST_BAD_REQUEST,
            Ok(b) => {
                let id = u64::from_le_bytes(b);
                match self
                    .active
                    .iter()
                    .find(|op| op.id == id && !op.is_finished())
                {
                    Some(op) => {
                        self.ops.cancel(op);
                        ST_OK
                    }
                    None => ST_NOT_FOUND,
                }
            }
        };
        port.reply(MSG_MD_REPLY, msg.seq, &reply_payload(st, &[]));
    }
}

impl Session for OpsSession {
    fn request(&mut self, port: &Arc<Port>, msg: &Msg) {
        match msg.kind {
            MSG_OP_START => self.start(port, msg),
            MSG_OP_CANCEL => self.cancel(port, msg),
            _ => self.inner.request(port, msg),
        }
    }
}

impl Drop for OpsSession {
    /// The connection is gone: nobody will hear about its ops, so stop them.
    fn drop(&mut self) {
        for op in &self.active {
            if !op.is_finished() {
                self.ops.cancel(op);
            }
        }
    }
}
