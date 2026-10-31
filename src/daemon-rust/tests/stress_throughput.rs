use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU32, Ordering},
    time::Instant,
};

use gungnird::{
    md::Ident,
    store::{Store, StoreConfig},
};

static TEST_COUNTER: AtomicU32 = AtomicU32::new(0);

fn get_peak_rss_kib() -> u64 {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
    let ret = unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) };
    if ret == 0 {
        let usage = unsafe { usage.assume_init() };
        usage.ru_maxrss as u64
    } else {
        0
    }
}

/// A fresh store dir for this test process under the repo's .build/tmp, created 0700 and
/// set to exactly 0700 whatever the umask: with umask 0000 a plain create_dir_all made it
/// 0777, and the store (rightly) refuses a group/world-writable directory.
fn temp_db_path() -> PathBuf {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    let id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../.build/tmp")
        .join(format!("stress-bench-{}", std::process::id()));
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)
        .unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    dir.join(format!("stress_{id}.db"))
}

fn remove_db(db_path: &std::path::Path) {
    let _ = fs::remove_file(db_path);
    let _ = fs::remove_file(format!("{}-wal", db_path.display()));
    let _ = fs::remove_file(format!("{}-shm", db_path.display()));
    if let Some(dir) = db_path.parent() {
        let _ = fs::remove_dir(dir); // only once empty: the other test may still use it
    }
}

fn ident(i: usize) -> Ident {
    Ident {
        fs_uuid: "00000000-0000-0000-0000-000000000001".to_string(),
        subvol_id: 0,
        inode_num: (100_000 + i) as u64,
        generation: 1,
        btime_sec: 0,
        btime_nsec: 0,
    }
}

/// Correctness only (default suite, no wall-clock or RSS limits): seed 5,000 linked
/// entries, update half of them, then remove them through `removed_paths` in batches;
/// every entry is gone afterwards and the counts add up.
#[test]
fn batch_removal_drops_every_linked_entry_5k() {
    const N: usize = 5_000;
    const BATCH: usize = 500;
    let db_path = temp_db_path();
    let mut store = Store::open(&db_path, StoreConfig::default()).expect("open store");
    let paths: Vec<(Vec<u8>, bool)> = (0..N)
        .map(|i| (format!("/bench/dir/file_{i}.txt").into_bytes(), false))
        .collect();
    for (i, (p, _)) in paths.iter().enumerate() {
        store
            .set_linked(
                &ident(i),
                "metadata::tag",
                b"\x01important",
                Some((p.as_slice(), 1)),
            )
            .expect("seed");
    }
    for (i, (p, _)) in paths.iter().enumerate().step_by(2) {
        store
            .set_linked(
                &ident(i),
                "metadata::viewed",
                b"\x01recent",
                Some((p.as_slice(), 1)),
            )
            .expect("update");
    }
    for i in [0, 1, N / 2, N - 1] {
        assert!(
            store
                .get(&ident(i), "metadata::tag")
                .expect("get")
                .is_some(),
            "entry {i} seeded"
        );
    }
    let mut dropped = 0;
    for chunk in paths.chunks(BATCH) {
        dropped += store.removed_paths(chunk).expect("batch removal");
    }
    assert!(
        dropped as usize >= N,
        "dropped {dropped} of {N} linked entries"
    );
    for i in 0..N {
        assert!(
            store
                .get(&ident(i), "metadata::tag")
                .expect("get")
                .is_none()
                && store
                    .get(&ident(i), "metadata::viewed")
                    .expect("get")
                    .is_none(),
            "entry {i} survived its path's removal"
        );
    }
    // Removing them again finds nothing.
    assert_eq!(store.removed_paths(&paths[..BATCH]).expect("again"), 0);
    drop(store);
    remove_db(&db_path);
}

/// The AGENTS.md §4 burst benchmark (50k events, wall-clock, p99 and peak-RSS SLOs).
/// Wall-clock and RSS limits are not a correctness gate on shared or loaded machines, so
/// it is out of the default suite (D-053 PR-F011, D-055). The CI job `rust:perf` runs
/// it, in scheduled and manually started pipelines only, with
/// `cargo test --release --test stress_throughput -- --ignored`; a missed SLO fails
/// that pipeline (RC-F025).
#[test]
#[ignore = "perf benchmark with wall-clock/RSS SLOs: CI job rust:perf (D-055, RC-F025)"]
fn test_batch_removal_and_throughput_benchmark_50k() {
    let db_path = temp_db_path();
    let _ = fs::remove_file(&db_path);

    let mut store = Store::open(&db_path, StoreConfig::default()).expect("open store");

    const TOTAL_EVENTS: usize = 50_000;
    const BATCH_SIZE: usize = 2_500;

    let mut idents = Vec::with_capacity(BATCH_SIZE);
    let mut paths = Vec::with_capacity(BATCH_SIZE);

    for i in 0..BATCH_SIZE {
        let id = Ident {
            fs_uuid: "00000000-0000-0000-0000-000000000001".to_string(),
            subvol_id: 0,
            inode_num: (100_000 + i) as u64,
            generation: 1,
            btime_sec: 0,
            btime_nsec: 0,
        };
        let path = format!("/bench/dir/file_{i}.txt").into_bytes();
        idents.push(id);
        paths.push((path, false));
    }

    // Pre-populate with batch entries
    for (id, (p, _)) in idents.iter().zip(paths.iter()) {
        store
            .set_linked(
                id,
                "metadata::tag",
                b"\x01important",
                Some((p.as_slice(), 1)),
            )
            .expect("initial seed");
    }

    // Benchmark the 50,000 file deletion and update event burst
    let mut latencies = Vec::with_capacity(TOTAL_EVENTS / BATCH_SIZE);
    let burst_start = Instant::now();
    let mut processed = 0;

    while processed < TOTAL_EVENTS {
        let batch_start = Instant::now();
        let dropped = store.removed_paths(&paths).expect("batch removal");
        let elapsed = batch_start.elapsed();

        let per_op_lat = elapsed.as_secs_f64() / paths.len() as f64;
        latencies.push(per_op_lat);

        assert!(dropped > 0 || processed > 0);
        processed += paths.len();

        // Alternate with fast batch updates
        if processed < TOTAL_EVENTS {
            let update_start = Instant::now();
            for (id, (p, _)) in idents.iter().zip(paths.iter()).take(500) {
                store
                    .set_linked(
                        id,
                        "metadata::viewed",
                        b"\x01recent",
                        Some((p.as_slice(), 1)),
                    )
                    .expect("batch update");
            }
            let update_elapsed = update_start.elapsed();
            let per_update_lat = update_elapsed.as_secs_f64() / 500.0;
            latencies.push(per_update_lat);
            processed += 500;
        }
    }

    let total_duration = burst_start.elapsed();

    // Calculate p99 latency
    latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let p99_idx = (latencies.len() as f64 * 0.99).min((latencies.len() - 1) as f64) as usize;
    let p99_latency_sec = latencies[p99_idx];

    // Measure RSS
    let peak_rss_kib = get_peak_rss_kib();
    let peak_rss_mib = peak_rss_kib as f64 / 1024.0;

    println!(
        "Benchmark Results (50,000 events):\n  Total Wall-clock Time: {:.3}s (SLO: < 1.5s)\n  Per-op p99 Latency: {:.4}ms (SLO: < 1.0ms)\n  Peak RSS: {:.2} MiB (SLO: < 40 MiB)",
        total_duration.as_secs_f64(),
        p99_latency_sec * 1000.0,
        peak_rss_mib
    );

    // Verify SLOs from AGENTS.md §4:
    assert!(
        total_duration.as_secs_f64() < 1.5,
        "Total burst duration {:.3}s exceeded SLO of 1.5s",
        total_duration.as_secs_f64()
    );
    assert!(
        p99_latency_sec < 0.001,
        "p99 latency {:.4}ms exceeded SLO of 1.0ms",
        p99_latency_sec * 1000.0
    );
    assert!(
        peak_rss_mib < 40.0,
        "Peak RSS {:.2} MiB exceeded SLO of 40 MiB",
        peak_rss_mib
    );

    drop(store);
    remove_db(&db_path);
}
