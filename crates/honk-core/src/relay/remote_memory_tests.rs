use super::{RELAY_BUF_IDLE_SHRINK, RELAY_BUF_MIN, RELAY_BUF_SIZE, REMOTE_COPY_BUFFER_MEMORY};
use super::{RelayProgress, relay_remote_tcp};
use futures::FutureExt;
use stats_alloc::{INSTRUMENTED_SYSTEM, Stats};
use std::cell::RefCell;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::Relaxed};
use std::task::{Context, Poll, ready};
use tokio::io::{AsyncBufRead, AsyncRead, AsyncWrite, ReadBuf};

#[derive(Default)]
struct Samples {
    snapshots: [Stats; 6],
    count: usize,
}

thread_local! {
    static SAMPLES: RefCell<Option<Samples>> = const { RefCell::new(None) };
}

fn sample() {
    SAMPLES.with_borrow_mut(|samples| {
        if let Some(samples) = samples {
            samples.snapshots[samples.count] = INSTRUMENTED_SYSTEM.stats();
            samples.count += 1;
        }
    });
}

// Called while the replacement and the previous buffer are both live.
pub(super) fn observe_buffer_allocation() {
    sample();
}

struct Source<'a> {
    data: &'a [u8],
    visible: &'a AtomicUsize,
    eof: &'a AtomicBool,
    pos: usize,
}

impl AsyncBufRead for Source<'_> {
    fn poll_fill_buf(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        let source = self.get_mut();
        let visible = &source.data[source.pos..source.visible.load(Relaxed)];
        if visible.is_empty() && !source.eof.load(Relaxed) {
            Poll::Pending
        } else {
            Poll::Ready(Ok(visible))
        }
    }

    fn consume(mut self: Pin<&mut Self>, n: usize) {
        self.pos += n;
    }
}

impl AsyncRead for Source<'_> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let bytes = ready!(self.as_mut().poll_fill_buf(cx))?;
        let n = bytes.len().min(buf.remaining());
        if n == RELAY_BUF_SIZE {
            // The old small buffer has been dropped. The next pending read arms the timer.
            sample();
        }
        buf.put_slice(&bytes[..n]);
        self.consume(n);
        Poll::Ready(Ok(()))
    }
}

struct Sink<'a> {
    data: &'a mut [u8],
    borrowed: Option<&'a [u8]>,
    pos: usize,
    pending_writes: usize,
    retry: bool,
    shutdowns: usize,
}

impl<'a> Sink<'a> {
    fn new(data: &'a mut [u8], borrowed: Option<&'a [u8]>) -> Self {
        Self {
            data,
            borrowed,
            pos: 0,
            pending_writes: 0,
            retry: false,
            shutdowns: 0,
        }
    }
}

const SHORT_WRITE: usize = 3;

impl AsyncWrite for Sink<'_> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let sink = self.get_mut();
        let mut n = bytes.len();
        if let Some(source) = sink.borrowed {
            assert_eq!(source[sink.pos..].as_ptr(), bytes.as_ptr());
            if !sink.retry {
                sink.retry = true;
                sink.pending_writes += 1;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            sink.retry = false;
            n = n.min(SHORT_WRITE);
        }
        sink.data[sink.pos..sink.pos + n].copy_from_slice(&bytes[..n]);
        sink.pos += n;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.shutdowns += 1;
        Poll::Ready(Ok(()))
    }
}

async fn drive_relay(measure: bool) {
    const PAYLOAD: &[u8] = b"borrowed upload across short writes";
    let upload = PAYLOAD;
    let download: Vec<_> = (0..2 * (RELAY_BUF_MIN + RELAY_BUF_SIZE))
        .map(|i| (i % 251) as u8)
        .collect();
    let mut upload_output = [0; PAYLOAD.len()];
    let mut download_output = vec![0; download.len()];
    let upload_visible = AtomicUsize::new(0);
    let download_visible = AtomicUsize::new(0);
    let eof = AtomicBool::new(false);
    let client_read = Source {
        data: upload,
        visible: &upload_visible,
        eof: &eof,
        pos: 0,
    };
    let proxy_read = Source {
        data: &download,
        visible: &download_visible,
        eof: &eof,
        pos: 0,
    };
    let mut client_write = Sink::new(&mut download_output, None);
    let mut proxy_write = Sink::new(&mut upload_output, Some(upload));
    let progress = RelayProgress {
        upload: Default::default(),
        download: Default::default(),
        outbound: None,
        first_response: None,
        on_transfer: None,
    };
    let addr = ([127, 0, 0, 1], 1234).into();
    if measure {
        SAMPLES.set(Some(Samples::default()));
    }
    let start = INSTRUMENTED_SYSTEM.stats();
    let (initial, uploaded, armed, shrunk, rearmed, result) = {
        let proxy = tokio::io::join(proxy_read, &mut proxy_write);
        let mut relay = std::pin::pin!(relay_remote_tcp(
            (client_read, &mut client_write),
            proxy,
            (addr, addr),
            &progress,
            || 0,
        ));
        assert!(relay.as_mut().now_or_never().is_none());
        let initial = INSTRUMENTED_SYSTEM.stats();
        upload_visible.store(upload.len(), Relaxed);
        for _ in 0..=upload.len().div_ceil(SHORT_WRITE) {
            assert!(relay.as_mut().now_or_never().is_none());
        }
        let uploaded = INSTRUMENTED_SYSTEM.stats();
        assert_eq!(progress.upload.load(Relaxed), upload.len() as u64);

        download_visible.store(download.len() / 2, Relaxed);
        assert!(relay.as_mut().now_or_never().is_none());
        let armed = INSTRUMENTED_SYSTEM.stats();
        // Let the paused runtime actually fire the idle timer before its next relay poll.
        tokio::time::sleep(RELAY_BUF_IDLE_SHRINK + std::time::Duration::from_millis(2)).await;
        assert!(relay.as_mut().now_or_never().is_none());
        let shrunk = INSTRUMENTED_SYSTEM.stats();
        download_visible.store(download.len(), Relaxed);
        assert!(relay.as_mut().now_or_never().is_none());
        let rearmed = INSTRUMENTED_SYSTEM.stats();
        eof.store(true, Relaxed);
        let result = relay.as_mut().now_or_never().expect("both sources closed");
        (initial, uploaded, armed, shrunk, rearmed, result)
    };
    let end = INSTRUMENTED_SYSTEM.stats();
    let samples = SAMPLES.take();
    let stats = result.unwrap();
    assert_eq!(stats.client_to_proxy, upload.len() as u64);
    assert_eq!(stats.proxy_to_client, download.len() as u64);
    assert_eq!(stats.total_bytes, (upload.len() + download.len()) as u64);
    assert_eq!(
        proxy_write.pending_writes,
        upload.len().div_ceil(SHORT_WRITE)
    );
    assert_eq!((client_write.shutdowns, proxy_write.shutdowns), (2, 2));
    assert_eq!(&upload_output, upload);
    assert_eq!(download_output, download);
    if !measure {
        return;
    }
    let samples = samples.unwrap();
    assert_eq!(samples.count, samples.snapshots.len());
    let [small, grow, large, shrink, regrow, large_again] = samples.snapshots;
    let boundaries = [initial, uploaded, armed, shrunk, rearmed, end];
    let peak = samples
        .snapshots
        .into_iter()
        .chain(boundaries)
        .map(|s| {
            let delta = s - start;
            delta.bytes_allocated - delta.bytes_deallocated
        })
        .max()
        .unwrap();
    assert!(
        peak <= REMOTE_COPY_BUFFER_MEMORY,
        "measured relay peak {peak} exceeds reservation {REMOTE_COPY_BUFFER_MEMORY}"
    );

    // Reconcile every allocator event between probes, including any short-lived allocation.
    let min = RELAY_BUF_MIN;
    let max = RELAY_BUF_SIZE;
    let timer = size_of::<tokio::time::Sleep>();
    let mut previous = start;
    let mut events = |next, alloc: &[usize], free: &[usize]| {
        assert_eq!(
            next - previous,
            Stats {
                allocations: alloc.len(),
                bytes_allocated: alloc.iter().sum(),
                deallocations: free.len(),
                bytes_deallocated: free.iter().sum(),
                ..Stats::default()
            }
        );
        previous = next;
    };
    events(small, &[min], &[]);
    events(initial, &[], &[]);
    events(uploaded, &[], &[]);
    events(grow, &[max], &[]);
    events(large, &[], &[min]);
    events(armed, &[timer], &[]);
    events(shrink, &[min], &[timer]);
    events(shrunk, &[], &[max]);
    events(regrow, &[max], &[]);
    events(large_again, &[], &[min]);
    events(rearmed, &[timer], &[]);
    events(end, &[], &[max, timer]);
    let lifecycle = end - start;
    assert_eq!(lifecycle.bytes_allocated, lifecycle.bytes_deallocated);
    let upload_delta = uploaded - initial;
    println!("P11_RELAY_PEAK_BYTES={peak}");
    println!("P11_RELAY_UPLOAD_ALLOCATIONS={}", upload_delta.allocations);
    println!(
        "P11_RELAY_UPLOAD_REALLOCATIONS={}",
        upload_delta.reallocations
    );
}

#[test]
fn remote_relay_heap_lifecycle() {
    const CHILD: &str = "HONK_REMOTE_RELAY_HEAP_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "relay::remote_memory_tests::remote_relay_heap_lifecycle",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("P11_RELAY_PEAK_BYTES="),
            "{stdout}{}",
            String::from_utf8_lossy(&output.stderr)
        );
        print!("{stdout}");
        return;
    }
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .start_paused(true)
        .build()
        .unwrap()
        .block_on(async {
            drive_relay(false).await;
            drive_relay(true).await;
        });
}
