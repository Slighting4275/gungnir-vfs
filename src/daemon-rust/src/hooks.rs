//! Test hooks: fault injection and knobs the integration tests turn from outside the
//! process. They are read from the environment once, at start, into one [`Hooks`] value
//! that the daemon passes into each part's configuration; no other code reads them.
//!
//! Only builds with the cargo feature `test-hooks` honour them (never a default feature;
//! CI checks the shipped binary has none). Any other build leaves every field at its
//! default and only warns about a hook variable that is set.

use std::{ffi::OsString, path::PathBuf, time::Duration};

use crate::{health, ipc, ops, vfssvc};

/// A worker started under a uring engine reports a plain-syscall fallback, as if a
/// restricted ring had not reached it: the mixed-engine refusal (DIR-A2-F01).
pub const MIXED_RINGS_ENV: &str = "GUNGNIR_TEST_MIXED_RINGS";
/// The upgrade drain's bound in ms, instead of 30 s.
pub const DRAIN_MS_ENV: &str = "GUNGNIR_TEST_DRAIN_MS";
/// Installing the seccomp filter fails as if the kernel had no TSYNC: the refusal path.
pub const TSYNC_FAIL_ENV: &str = "GUNGNIR_TEST_TSYNC_FAIL";

/// Every hook variable, for the warning in builds without the feature.
pub const ALL: [&str; 9] = [
    health::FAKE_HUNG_ENV,
    ops::SLOW_OPS_ENV,
    ops::PAUSE_AT_ENV,
    ops::RING_LOSS_ENV,
    MIXED_RINGS_ENV,
    DRAIN_MS_ENV,
    TSYNC_FAIL_ENV,
    ipc::UPGRADE_EXE_ENV,
    vfssvc::TEST_TOP_ENV,
];

/// What the hooks ask for. The default asks for nothing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Hooks {
    /// [`health::FAKE_HUNG_ENV`]: fake FUSE mounts whose health probes never return.
    pub fake_hung: Vec<Vec<u8>>,
    /// [`ops::SLOW_OPS_ENV`]: file ops sleep this long per chunk or directory entry.
    pub slow_ops: Option<Duration>,
    /// [`ops::PAUSE_AT_ENV`]: every copy holds at this point until it is stopped.
    pub pause_at: Option<ops::PausePoint>,
    /// [`ops::RING_LOSS_ENV`]: the first worker to pick up an op loses its ring, and the
    /// sandbox's ring pool is exhausted (A2-MGR-03).
    pub ring_loss: bool,
    /// [`MIXED_RINGS_ENV`].
    pub mixed_rings: bool,
    /// [`DRAIN_MS_ENV`].
    pub drain: Option<Duration>,
    /// [`TSYNC_FAIL_ENV`].
    pub tsync_fail: bool,
    /// [`ipc::UPGRADE_EXE_ENV`]: the live upgrade re-execs this path instead.
    pub upgrade_exe: Option<PathBuf>,
    /// [`vfssvc::TEST_TOP_ENV`]: one more trash volume.
    pub trash_top: Option<PathBuf>,
}

impl Hooks {
    /// The hooks the environment sets.
    #[must_use]
    pub fn from_env() -> Self {
        Self::from_vars(|k| std::env::var_os(k))
    }

    /// The hooks `get` sets (an environment of the caller's choosing).
    #[must_use]
    pub fn from_vars(get: impl Fn(&str) -> Option<OsString>) -> Self {
        #[cfg(not(feature = "test-hooks"))]
        {
            for name in ALL {
                if get(name).is_some() {
                    eprintln!("gungnird: {name} ignored (built without the test-hooks feature)");
                }
            }
            Self::default()
        }
        #[cfg(feature = "test-hooks")]
        {
            let ms = |name: &str| {
                get(name).map(|v| {
                    Duration::from_millis(
                        v.to_str()
                            .and_then(|s| s.trim().parse::<u64>().ok())
                            .unwrap_or(0),
                    )
                })
            };
            let h = Self {
                fake_hung: get(health::FAKE_HUNG_ENV)
                    .map(health::fake_hung_path)
                    .unwrap_or_default(),
                slow_ops: ms(ops::SLOW_OPS_ENV),
                pause_at: get(ops::PAUSE_AT_ENV)
                    .and_then(|v| v.to_str().and_then(ops::PausePoint::parse)),
                ring_loss: get(ops::RING_LOSS_ENV).is_some(),
                mixed_rings: get(MIXED_RINGS_ENV).is_some(),
                drain: ms(DRAIN_MS_ENV),
                tsync_fail: get(TSYNC_FAIL_ENV).is_some(),
                upgrade_exe: get(ipc::UPGRADE_EXE_ENV).map(PathBuf::from),
                trash_top: get(vfssvc::TEST_TOP_ENV).map(PathBuf::from),
            };
            if h != Self::default() {
                eprintln!("gungnird: TEST HOOKS: {h:?}");
            }
            h
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with(pairs: &[(&str, &str)]) -> Hooks {
        let pairs: Vec<(String, OsString)> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), OsString::from(v)))
            .collect();
        Hooks::from_vars(|k| pairs.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone()))
    }

    #[test]
    fn nothing_set_asks_for_nothing() {
        assert_eq!(with(&[]), Hooks::default());
    }

    #[cfg(feature = "test-hooks")]
    #[test]
    fn hooks_are_read_once_into_one_value() {
        let h = with(&[
            (ops::SLOW_OPS_ENV, "40"),
            (ops::PAUSE_AT_ENV, "mid-copy"),
            (ops::RING_LOSS_ENV, "1"),
            (DRAIN_MS_ENV, "250"),
            (health::FAKE_HUNG_ENV, "/x/../y/hung"),
            (vfssvc::TEST_TOP_ENV, "/vol"),
        ]);
        assert_eq!(h.slow_ops, Some(Duration::from_millis(40)));
        assert_eq!(h.pause_at, Some(ops::PausePoint::MidCopy));
        assert!(h.ring_loss && !h.mixed_rings && !h.tsync_fail);
        assert_eq!(h.drain, Some(Duration::from_millis(250)));
        assert_eq!(h.fake_hung, [b"/y/hung".to_vec()]);
        assert_eq!(h.trash_top, Some(PathBuf::from("/vol")));
        // A fake mount at the root would hang everything: refused.
        assert!(with(&[(health::FAKE_HUNG_ENV, "/")]).fake_hung.is_empty());
    }

    #[cfg(not(feature = "test-hooks"))]
    #[test]
    fn a_release_build_honours_no_hook() {
        let all: Vec<(&str, &str)> = ALL.iter().map(|n| (*n, "/x")).collect();
        assert_eq!(with(&all), Hooks::default());
    }
}
