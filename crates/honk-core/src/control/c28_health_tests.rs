use crate::control::{ControlPlane, c20_tests::control_plane, reload_tests};
use honk_config::{Config, node::Node, types::NodeProtocol};
use honk_outbound::alive::{HttpProbeResult, HttpProber};
use honk_outbound::proxy::{ProtocolEntry, ProxyRegistry, ProxyStream, TcpOutbound};
use parking_lot::Mutex;
use std::{future::Future, net::SocketAddr, pin::Pin, sync::Arc, time::Duration};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

#[derive(Debug)]
struct DirectConnectHandler;

#[async_trait::async_trait]
impl TcpOutbound for DirectConnectHandler {
    async fn dial(
        &self,
        _node: &Node,
        target: SocketAddr,
        domain: Option<&str>,
        timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        Ok(ProxyStream {
            stream: Box::new(tokio::time::timeout(timeout, TcpStream::connect(target)).await??),
            target_addr: target,
            target_domain: domain.map(str::to_owned),
        })
    }
}

struct PeriodProbe(tokio::sync::mpsc::UnboundedSender<tokio::time::Instant>);
impl HttpProber for PeriodProbe {
    fn probe_http(
        &self,
        _: &str,
        _: SocketAddr,
        _: &str,
        _: Duration,
    ) -> Pin<Box<dyn Future<Output = HttpProbeResult> + Send + 'static>> {
        let _ = self.0.send(tokio::time::Instant::now());
        Box::pin(async { HttpProbeResult::WarmSuccess(Duration::from_millis(1)) })
    }
}

fn health_config(url: String) -> Config {
    let mut config = reload_tests::score_reload_config(50);
    config.global.nfqueue_enable = false;
    config.global.check_interval_secs = 30;
    config.global.tcp_check_url = vec![url];
    config.global.tcp_check_http_method = "HEAD".into();
    config
}

#[tokio::test(start_paused = true)]
async fn c28_health_reload_retains_old_period_after_rejection() {
    let old = health_config("http://127.0.0.1:18080/".into());
    let cp = control_plane(old.clone()).await;
    let alive = cp.alive_set();
    let (calls, mut observations) = tokio::sync::mpsc::unbounded_channel();
    alive
        .set_http_probe(
            Arc::new(PeriodProbe(calls)),
            old.global.tcp_check_url[0].clone(),
            "HEAD".into(),
        )
        .await;
    let task = alive.spawn_health_check_loop(Duration::from_secs(30), Duration::from_secs(1));
    let first = observations.recv().await.unwrap();
    // Both registered leaves are probed in each cycle.
    observations.recv().await.unwrap();
    let mut candidate = old.clone();
    candidate.global.check_interval_secs = 60;
    assert!(
        !cp.reload_runtime_config(candidate, Default::default())
            .await
    );
    assert_eq!(
        observations.recv().await.unwrap() - first,
        Duration::from_secs(30)
    );
    assert_eq!(cp.config_handle().read().await.as_ref(), &old);
    task.abort();
    let _ = task.await;
}

async fn http_fixture() -> (
    ControlPlane,
    Arc<Mutex<Vec<String>>>,
    tokio::task::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let old = health_config(format!(
        "http://127.0.0.1:{}/old-path?old=1",
        listener.local_addr().unwrap().port()
    ));
    let requests = Arc::new(Mutex::new(Vec::new()));
    let observed = requests.clone();
    let task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let observed = observed.clone();
            tokio::spawn(async move {
                let mut stream = BufReader::new(stream);
                loop {
                    let mut request = String::new();
                    while !request.ends_with("\r\n\r\n") {
                        match stream.read_line(&mut request).await {
                            Ok(0) | Err(_) => return,
                            Ok(_) => {}
                        }
                    }
                    observed.lock().push(request);
                    if stream
                        .get_mut()
                        .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
            });
        }
    });
    let cp = control_plane(old.clone()).await;
    let mut registry = ProxyRegistry::new();
    registry.register(ProtocolEntry::new(
        NodeProtocol::Socks5,
        Arc::new(DirectConnectHandler),
    ));
    let prober = Arc::new(crate::control::probers::ProxyHttpProber::new(
        cp.config_handle(),
        Arc::new(registry),
        cp.runtime_registry(),
        "HEAD".into(),
        cp.group_manager(),
    ));
    cp.alive_set()
        .set_http_probe(prober, old.global.tcp_check_url[0].clone(), "HEAD".into())
        .await;
    (cp, requests, task)
}

async fn reject_http_change(change: fn(&mut Config)) {
    let (cp, requests, task) = http_fixture().await;
    let old = cp.config_handle().read().await.clone();
    let mut candidate = old.as_ref().clone();
    change(&mut candidate);
    assert!(
        !cp.reload_runtime_config(candidate, Default::default())
            .await
    );
    cp.alive_set()
        .run_health_check_cycle(Duration::from_secs(1))
        .await;
    assert_eq!(cp.config_handle().read().await.as_ref(), old.as_ref());
    let requests = requests.lock();
    assert!(!requests.is_empty(), "real HTTP probe made no request");
    assert!(
        requests
            .iter()
            .all(|request| request.starts_with("HEAD /old-path?old=1 HTTP/1.1"))
    );
    task.abort();
}

#[tokio::test]
async fn c28_first_http_url_rejection_retains_installed_request() {
    reject_http_change(|config| {
        config.global.tcp_check_url[0] = "http://127.0.0.1:1/new-path?new=1".into()
    })
    .await;
}

#[tokio::test]
async fn c28_http_method_rejection_retains_installed_request() {
    reject_http_change(|config| config.global.tcp_check_http_method = "GET".into()).await;
}

#[tokio::test]
async fn c28_tls_rejection_retains_consumer_mode() {
    honk_outbound::tls::set_tls_mode("tls");
    reject_http_change(|config| config.global.tls_implementation = "utls".into()).await;
    assert!(!honk_outbound::tls::chrome_mode());
}

#[tokio::test]
async fn c28_effectively_equal_health_inputs_remain_admissible() {
    for change in [
        |config: &mut Config| config.global.tcp_check_http_method.clear(),
        |config: &mut Config| {
            config
                .global
                .tcp_check_url
                .push("http://127.0.0.1:1/later".into())
        },
        |config: &mut Config| config.global.tls_implementation = "TLS".into(),
        |config: &mut Config| config.global.utls_imitate = "firefox".into(),
    ] {
        let old = health_config("http://127.0.0.1:18080/".into());
        let cp = control_plane(old.clone()).await;
        let mut candidate = old;
        change(&mut candidate);
        assert!(
            cp.reload_runtime_config(candidate.clone(), Default::default())
                .await
        );
        assert_eq!(cp.config_handle().read().await.as_ref(), &candidate);
    }
    let mut old = health_config(String::new());
    let cp = control_plane(old.clone()).await;
    old.global.tcp_check_url.clear();
    old.global.tcp_check_http_method = "POST".into();
    assert!(cp.reload_runtime_config(old, Default::default()).await);
}
