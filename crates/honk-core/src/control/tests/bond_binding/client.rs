use super::{BLOCK, CLIENT, CLIENT_TEST, TIMEOUT, UDP_PORT, in_test_netns};
use anyhow::{Context, ensure};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::OwnedFd;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout};

/// A different PID is mandatory for WAN: the control-plane PID is exempt. The
/// command pipe pauses an established socket while the parent changes members.
pub(super) struct Client {
    process: Child,
    input: Option<ChildStdin>,
    output: BufReader<ChildStdout>,
    pub(super) local: SocketAddr,
}

impl Client {
    pub(super) async fn start(
        kind: &str,
        source: Ipv4Addr,
        target: SocketAddr,
        netns: Option<&OwnedFd>,
    ) -> anyhow::Result<Self> {
        let spawn = || {
            tokio::process::Command::new(std::env::current_exe().expect("test executable"))
                .args([CLIENT_TEST, "--ignored", "--exact", "--nocapture"])
                .env(CLIENT, format!("{kind},{source},{target}"))
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .kill_on_drop(true)
                .spawn()
        };
        let mut process = match netns {
            Some(netns) => in_test_netns(netns, spawn),
            None => spawn(),
        }?;
        let mut client = Self {
            input: Some(process.stdin.take().context("client stdin")?),
            output: BufReader::new(process.stdout.take().context("client stdout")?),
            process,
            local: "0.0.0.0:0".parse()?,
        };
        client.local = client.line().await?.parse()?;
        Ok(client)
    }

    async fn line(&mut self) -> anyhow::Result<String> {
        tokio::time::timeout(TIMEOUT, async {
            loop {
                let mut line = String::new();
                ensure!(
                    self.output.read_line(&mut line).await? != 0,
                    "client closed its output"
                );
                if let Some((_, value)) = line.split_once("BOND ") {
                    return Ok(value.trim().to_owned());
                }
            }
        })
        .await
        .context("client operation timed out")?
    }

    pub(super) async fn command(&mut self, command: &str) -> anyhow::Result<()> {
        self.input
            .as_mut()
            .context("client closed")?
            .write_all(format!("{command}\n").as_bytes())
            .await?;
        ensure!(self.line().await? == "ok", "client command failed");
        Ok(())
    }

    pub(super) async fn rounds(&mut self, count: usize) -> anyhow::Result<()> {
        self.command(&format!("rounds {count}")).await
    }

    pub(super) async fn finish(mut self) -> anyhow::Result<()> {
        drop(self.input.take());
        let status = tokio::time::timeout(TIMEOUT, self.process.wait()).await??;
        ensure!(status.success(), "client failed: {status}");
        Ok(())
    }
}

pub(super) fn client_main(spec: &str) -> anyhow::Result<()> {
    use std::io::{BufRead, Read, Write};
    let fields = spec.split(',').collect::<Vec<_>>();
    ensure!(fields.len() == 3, "client spec");
    let source = fields[1].parse::<IpAddr>()?;
    let target = fields[2].parse::<SocketAddr>()?;
    let (mut tcp, udp, local) = if fields[0] == "tcp" {
        let stream = std::net::TcpStream::connect_timeout(&target, TIMEOUT)?;
        stream.set_read_timeout(Some(TIMEOUT))?;
        stream.set_write_timeout(Some(TIMEOUT))?;
        let local = stream.local_addr()?;
        (Some(stream), None, local)
    } else {
        let socket = std::net::UdpSocket::bind(SocketAddr::new(source, 0))?;
        socket.set_read_timeout(Some(TIMEOUT))?;
        let local = socket.local_addr()?;
        (None, Some(socket), local)
    };
    println!("BOND {local}");
    std::io::stdout().flush()?;
    let mut serial = 0u32;
    for command in std::io::stdin().lock().lines() {
        let command = command?;
        if command == "foreign" {
            let mut reply = [0; BLOCK];
            loop {
                let (size, from) = udp.as_ref().context("foreign UDP")?.recv_from(&mut reply)?;
                if from == target && size == BLOCK {
                    continue;
                }
                ensure!(
                    &reply[..size] == b"foreign"
                        && from.ip() == target.ip()
                        && from.port() == UDP_PORT + 1,
                    "foreign reply lost framing/source"
                );
                break;
            }
        } else {
            let count = command
                .strip_prefix("rounds ")
                .context("client command")?
                .parse::<usize>()?;
            for _ in 0..count {
                serial += 1;
                let mut request = [0x6b; BLOCK];
                request[..4].copy_from_slice(&serial.to_be_bytes());
                let mut reply = [0; BLOCK];
                if let Some(tcp) = tcp.as_mut() {
                    tcp.write_all(&request)?;
                    tcp.read_exact(&mut reply)?;
                } else {
                    let socket = udp.as_ref().context("UDP socket")?;
                    socket.send_to(&request, target)?;
                    loop {
                        let (size, from) = socket.recv_from(&mut reply)?;
                        ensure!(
                            size == BLOCK && from == target,
                            "UDP reply lost payload/source"
                        );
                        if reply[..4] == request[..4] {
                            break;
                        } // broadcast mode may duplicate a reply.
                    }
                }
                ensure!(request == reply, "reply data changed");
            }
        }
        println!("BOND ok");
        std::io::stdout().flush()?;
    }
    Ok(())
}
