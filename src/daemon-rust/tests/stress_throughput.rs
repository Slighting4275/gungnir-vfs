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

fn temp_db_path() -> PathBuf {
    let id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = PathBuf::from(".build/tmp/stress-bench");
    fs::create_dir_all(&dir).unwrap();
    dir.join(format!("stress_{id}_{}.db", std::process::id()))
}

#[test]
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

    let _ = fs::remove_file(&db_path);
    let _ = fs::remove_file(format!("{}-wal", db_path.display()));
    let _ = fs::remove_file(format!("{}-shm", db_path.display()));
}
