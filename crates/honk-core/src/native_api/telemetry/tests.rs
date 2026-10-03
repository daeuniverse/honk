use super::super::types::{TrafficBytes, TrafficConnections, TrafficRates};
use super::*;

fn traffic(at: SystemTime, rate: Option<u64>) -> TrafficSummary {
    TrafficSummary {
        scope: "visible",
        observed_by: "userspace",
        counter_since: Some(timestamp(SystemTime::UNIX_EPOCH)),
        sampled_at: Some(timestamp(at)),
        connections: TrafficConnections {
            tcp: None,
            udp: None,
            total: rate,
        },
        bytes: TrafficBytes {
            upload: None,
            download: None,
        },
        rates: rate.map(|value| TrafficRates {
            window_seconds: 1.0,
            upload_bytes_per_second: Some(value.to_string()),
            download_bytes_per_second: Some((value * 2).to_string()),
        }),
    }
}

#[test]
fn histories_preserve_gaps_nulls_and_newest_anchored_thinning() {
    let telemetry = Telemetry::new(true, true);
    let base = SystemTime::UNIX_EPOCH + Duration::from_secs(1000);
    let start = Instant::now();
    for (index, seconds) in [0, 1, 4, 5, 8, 9, 10].into_iter().enumerate() {
        let at = base + Duration::from_secs(seconds);
        telemetry.record(
            &traffic(at, (index != 3).then_some(index as u64 + 1)),
            MemoryReading::default(),
            at,
            start + Duration::from_secs(seconds),
        );
    }
    let samples = telemetry.state.lock();
    let ring = samples.traffic.as_ref().unwrap();
    let observed = base + Duration::from_secs(10);
    let (stride, all) = history(ring, observed, 20, 600);
    assert_eq!(stride, 1);
    assert_eq!(
        all.iter()
            .map(|point| point.sampled_at.clone())
            .collect::<Vec<_>>(),
        [0, 1, 4, 5, 8, 9, 10].map(|second| timestamp(base + Duration::from_secs(second)))
    );
    let (stride, thinned) = history(ring, observed, 20, 3);
    assert_eq!(stride, 3);
    assert_eq!(
        thinned
            .iter()
            .map(|point| point.upload_bytes_per_second.as_deref())
            .collect::<Vec<_>>(),
        [Some("1"), None, Some("7")]
    );
    assert_eq!(thinned[1].connections, None);
    let (_, one) = history(ring, observed, 20, 1);
    assert_eq!(one[0].sampled_at, timestamp(observed));
    let (_, exclusive) = history(ring, observed, 2, 600);
    assert_eq!(
        exclusive
            .iter()
            .map(|point| point.sampled_at.clone())
            .collect::<Vec<_>>(),
        [9, 10].map(|second| timestamp(base + Duration::from_secs(second)))
    );
    let (_, before_sampling) = history(ring, base - Duration::from_secs(1), 20, 600);
    assert!(before_sampling.is_empty());
}

#[test]
fn histories_bound_capacity_age_and_allocate_nothing_when_disabled() {
    let telemetry = Telemetry::new(true, true);
    let now = Instant::now();
    let base = SystemTime::UNIX_EPOCH + Duration::from_secs(1000);
    for index in 0..=600 {
        let at = base + Duration::from_millis(index);
        telemetry.record(&traffic(at, Some(index)), MemoryReading::default(), at, now);
    }
    {
        let mut samples = telemetry.state.lock();
        assert_eq!(samples.traffic.as_ref().unwrap().len(), 600);
        assert_eq!(samples.memory.as_ref().unwrap().len(), 600);
        assert_eq!(
            samples
                .traffic
                .as_ref()
                .unwrap()
                .front()
                .unwrap()
                .value
                .sampled_at,
            timestamp(base + Duration::from_millis(1))
        );
        prune(samples.traffic.as_mut().unwrap(), now + RETENTION);
        prune(samples.memory.as_mut().unwrap(), now + RETENTION);
        assert!(samples.traffic.as_ref().unwrap().is_empty());
        assert!(samples.memory.as_ref().unwrap().is_empty());
    }
    let disabled = Telemetry::new(false, false);
    disabled.record(
        &traffic(base, Some(99)),
        MemoryReading {
            rss: Some(4096),
            cgroup: None,
            ebpf: None,
        },
        base,
        now,
    );
    assert!(!disabled.record_traffic());
    assert!(!disabled.record_memory());
    let samples = disabled.state.lock();
    assert!(samples.traffic.is_none());
    assert!(samples.memory.is_none());
    assert_eq!(samples.latest.rss, Some(4096));
    assert_eq!(samples.metrics, ["process.rss_bytes"]);
}

#[test]
fn history_queries_reject_unknown_duplicate_and_excess_limits() {
    let id = RequestId("test".into());
    assert_eq!(
        history_query(&"/history".parse().unwrap(), &id).unwrap(),
        (600, 600)
    );
    assert_eq!(
        history_query(
            &"/history?window_seconds=1&max_points=2".parse().unwrap(),
            &id
        )
        .unwrap(),
        (1, 2)
    );
    for query in [
        "max_points=0",
        "max_points=601",
        "window_seconds=601",
        "window_seconds=-1",
        "window_seconds=1.5",
        "max_points=%2B1",
        "max_points=1&max_points=2",
        "unknown=1",
    ] {
        assert!(
            history_query(&format!("/history?{query}").parse().unwrap(), &id).is_err(),
            "{query}"
        );
    }
}

#[test]
fn cgroup_resolution_obeys_mount_roots_and_escaped_paths() {
    let mounts = "1 0 0:1 / /sys/fs/cgroup rw - cgroup2 cgroup rw\n2 0 0:1 /slice /private\\040mount rw - cgroup2 cgroup rw\n";
    assert_eq!(
        cgroup_directory("0::/slice/job\n", mounts),
        Some(PathBuf::from("/private mount/job"))
    );
    assert_eq!(
        cgroup_directory("0::/slice-other/job\n", mounts),
        Some(PathBuf::from("/sys/fs/cgroup/slice-other/job"))
    );
    assert_eq!(
        cgroup_directory("0::/\n", mounts),
        Some(PathBuf::from("/sys/fs/cgroup/"))
    );
    for member in [
        "0::/../escape\n",
        "0::relative\n",
        "0::/a\n0::/b\n",
        "1:memory:/slice/job\n",
    ] {
        assert_eq!(cgroup_directory(member, mounts), None);
    }
    assert_eq!(
        cgroup_directory(
            "0::/elsewhere\n",
            "1 0 0:1 /slice /cg rw - cgroup2 cgroup rw\n"
        ),
        None
    );
    assert_eq!(mount_path("/bad\\999path"), None);
    assert_eq!(rss("VmRSS:\t18446744073709551615 kB\n"), None);
    assert_eq!(
        cgroup_events("high 0\noom 3\noom_kill -1\n"),
        [Some(0), Some(3), None]
    );
    assert_eq!(
        cgroup_events("high 1\nhigh 2\noom 3 extra\n"),
        [None, None, None]
    );
}

#[tokio::test]
async fn memory_reads_real_files_and_preserves_unavailable_metrics() {
    let fixture = tempfile::tempdir().unwrap();
    let proc_self = fixture.path().join("proc");
    let cgroup_root = fixture.path().join("cgroup mount");
    let cgroup = cgroup_root.join("worker");
    std::fs::create_dir(&proc_self).unwrap();
    std::fs::create_dir_all(&cgroup).unwrap();
    std::fs::write(proc_self.join("status"), "Name:\thost\nVmRSS:\t4097 kB\n").unwrap();
    std::fs::write(proc_self.join("cgroup"), "0::/service/worker\n").unwrap();
    std::fs::write(
        proc_self.join("mountinfo"),
        format!(
            "1 0 0:1 /service {} rw,nosuid - cgroup2 cgroup rw\n",
            cgroup_root.display().to_string().replace(' ', "\\040")
        ),
    )
    .unwrap();
    std::fs::write(cgroup.join("memory.current"), "8589934593\n").unwrap();
    std::fs::write(cgroup.join("memory.max"), "max\n").unwrap();
    std::fs::write(
        cgroup.join("memory.events"),
        "low 0\nhigh 2\nmax 0\noom 3\noom_kill 4\n",
    )
    .unwrap();
    std::fs::write(
        cgroup.join("cgroup.procs"),
        format!("{}\n", std::process::id()),
    )
    .unwrap();
    let reading = read_memory(&proc_self).await;
    assert_eq!(reading.rss, Some(4097 * 1024));
    let group = reading.cgroup.as_ref().unwrap();
    assert_eq!(group.scope, "service");
    assert_eq!(group.current, Some(8589934593));
    assert_eq!(group.limit, None);
    assert!(group.limit_readable);
    assert_eq!(group.events, [Some(2), Some(3), Some(4)]);
    assert_eq!(
        reading.metrics().collect::<Vec<_>>(),
        [
            "process.rss_bytes",
            "cgroup.current_bytes",
            "cgroup.limit_bytes",
            "cgroup.events.high",
            "cgroup.events.oom",
            "cgroup.events.oom_kill"
        ]
    );
    std::fs::write(cgroup.join("memory.max"), "17179869184\n").unwrap();
    assert_eq!(
        read_memory(&proc_self).await.cgroup.unwrap().limit,
        Some(17179869184)
    );
    std::fs::write(proc_self.join("status"), "Name:\thost\n").unwrap();
    std::fs::write(cgroup.join("memory.current"), "-1\n").unwrap();
    std::fs::write(cgroup.join("memory.max"), "overflow\n").unwrap();
    std::fs::remove_file(cgroup.join("memory.events")).unwrap();
    let unavailable = read_memory(&proc_self).await;
    assert_eq!(unavailable.rss, None);
    assert!(unavailable.cgroup.is_none());
    assert!(unavailable.metrics().next().is_none());
    std::fs::write(
        proc_self.join("status"),
        format!("VmRSS: 1 kB\n{}", "x".repeat(64 * 1024)),
    )
    .unwrap();
    assert_eq!(read_memory(&proc_self).await.rss, None);
    assert!(bounded_read(proc_self.join("missing"), 128).await.is_none());
    std::fs::write(cgroup.join("memory.current"), [0xff, 0xfe]).unwrap();
    assert!(
        bounded_read(cgroup.join("memory.current"), 128)
            .await
            .is_none()
    );
}

#[tokio::test]
async fn sampler_observes_linux_process_without_enabling_history() {
    let telemetry = Telemetry::new(false, false);
    telemetry.sample(&traffic(SystemTime::now(), None)).await;
    let samples = telemetry.state.lock();
    assert!(samples.latest.rss.is_some_and(|rss| rss > 0));
    assert!(samples.metrics.contains(&"process.rss_bytes"));
    assert!(!samples.metrics.contains(&"kernel.ebpf_bytes"));
    assert!(samples.traffic.is_none());
    assert!(samples.memory.is_none());
}

#[tokio::test]
async fn cgroup_scope_distinguishes_service_shared_and_unreadable() {
    let fixture = tempfile::tempdir().unwrap();
    let group = fixture.path();
    let own = format!("{}\n", std::process::id());
    assert_eq!(cgroup_scope(group).await, "unknown");
    std::fs::write(group.join("cgroup.procs"), "").unwrap();
    assert_eq!(cgroup_scope(group).await, "unknown");
    std::fs::write(group.join("cgroup.procs"), &own).unwrap();
    std::fs::write(group.join("memory.current"), "1\n").unwrap();
    assert_eq!(cgroup_scope(group).await, "service");
    std::fs::create_dir(group.join("child")).unwrap();
    assert_eq!(cgroup_scope(group).await, "shared");
    std::fs::remove_dir(group.join("child")).unwrap();
    std::fs::write(group.join("cgroup.procs"), format!("1\n{own}")).unwrap();
    assert_eq!(cgroup_scope(group).await, "shared");
    std::fs::write(
        group.join("cgroup.procs"),
        format!("{own}{}\n", "9".repeat(4096)),
    )
    .unwrap();
    assert_eq!(cgroup_scope(group).await, "shared");
}

#[tokio::test]
async fn ebpf_bytes_sum_memlock_of_own_bpf_fds_only() {
    use std::os::unix::fs::symlink;
    let fixture = tempfile::tempdir().unwrap();
    let proc_self = fixture.path();
    let (fd, fdinfo) = (proc_self.join("fd"), proc_self.join("fdinfo"));
    std::fs::create_dir(&fd).unwrap();
    std::fs::create_dir(&fdinfo).unwrap();
    assert_eq!(ebpf_bytes(proc_self), None);
    let entries = [
        (
            "3",
            "anon_inode:bpf-map",
            Some("pos:\t0\nmap_type:\t1\nmemlock:\t4096\n"),
        ),
        (
            "4",
            "anon_inode:bpf-prog",
            Some("prog_type:\t3\nmemlock:\t8192\n"),
        ),
        (
            "5",
            "socket:[77]",
            Some("map_type:\t1\nmemlock:\t1000000\n"),
        ),
        (
            "6",
            "anon_inode:bpf-map",
            Some("pos:\t0\nmemlock:\t1000000\n"),
        ),
        ("7", "anon_inode:bpf-map", None),
    ];
    for (name, target, info) in entries {
        symlink(target, fd.join(name)).unwrap();
        if let Some(info) = info {
            std::fs::write(fdinfo.join(name), info).unwrap();
        }
    }
    assert_eq!(ebpf_bytes(proc_self), Some(4096 + 8192));
    let reading = read_memory(proc_self).await;
    assert_eq!(reading.ebpf.map(|(bytes, _)| bytes), Some(12288));
    assert!(
        reading
            .metrics()
            .any(|metric| metric == "kernel.ebpf_bytes")
    );
    for name in ["3", "4"] {
        std::fs::remove_file(fdinfo.join(name)).unwrap();
    }
    assert_eq!(ebpf_bytes(proc_self), None);
}
