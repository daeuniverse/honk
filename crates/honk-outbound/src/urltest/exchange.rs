use super::*;
use std::time::SystemTime;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

enum RoundError {
    Transport(anyhow::Error),
    Invalid(anyhow::Error),
}

impl RoundError {
    fn into_error(self) -> anyhow::Error {
        match self {
            Self::Transport(error) | Self::Invalid(error) => error,
        }
    }
}

fn h2_round_error(error: h2::Error, context: &'static str) -> RoundError {
    // A remote REFUSED_STREAM means the request was not processed (RFC 9113 §8.7).
    let refused =
        error.is_reset() && error.is_remote() && error.reason() == Some(h2::Reason::REFUSED_STREAM);
    let transport = error.is_io()
        || (error.is_go_away() && error.reason() == Some(h2::Reason::NO_ERROR))
        || refused;
    let error = anyhow::Error::new(error).context(context);
    if transport {
        RoundError::Transport(error)
    } else {
        RoundError::Invalid(error)
    }
}

fn request_with_method(
    request: &http::Request<()>,
    method: http::Method,
) -> anyhow::Result<http::Request<()>> {
    let target = request_target(request)?;
    build_http_probe_request(&target, method)
}

async fn h2_round(
    sender: &mut h2::client::SendRequest<bytes::Bytes>,
    request: &http::Request<()>,
    method: http::Method,
    reporter: &Option<ScoreReporter>,
    first_response: bool,
) -> Result<(ProbeMeasurement, http::StatusCode), RoundError> {
    std::future::poll_fn(|context| sender.poll_ready(context))
        .await
        .map_err(|error| h2_round_error(error, "HTTP/2 request readiness failed"))?;
    let outgoing = request_with_method(request, method.clone()).map_err(RoundError::Invalid)?;
    let start = Instant::now();
    let (response, _) = sender
        .send_request(outgoing, true)
        .map_err(|error| h2_round_error(error, "HTTP/2 request send failed"))?;
    let uri_bytes = request
        .uri()
        .authority()
        .map_or(0, |authority| authority.as_str().len())
        .saturating_add(
            request
                .uri()
                .path_and_query()
                .map_or(1, |target| target.as_str().len()),
        );
    reporter_tx(reporter, method.as_str().len().saturating_add(uri_bytes));
    let response = response
        .await
        .map_err(|error| h2_round_error(error, "HTTP/2 response failed"))?;
    if first_response {
        reporter_first_response(reporter);
    }
    reporter_rx(reporter, 1);
    // ponytail: locked h2 0.4.19 defaults missing :status; await a release containing hyperium/h2#959.
    Ok((
        ProbeMeasurement {
            latency: start.elapsed(),
            observed_at: SystemTime::now(),
        },
        response.status(),
    ))
}

/// Cold or warmed HTTP/2 requests, driven inline so cancellation drops the
/// actual connection instead of detaching an aborted driver.
pub(super) async fn exchange_http2<S>(
    stream: S,
    request: &http::Request<()>,
    reporter: &Option<ScoreReporter>,
    timeout: Duration,
    cold: bool,
) -> anyhow::Result<ProbeMeasurement>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut sender, connection) = tokio::time::timeout(
        timeout,
        h2::client::Builder::new()
            .enable_push(false)
            .max_local_error_reset_streams(Some(0))
            .reset_stream_duration(timeout.saturating_mul(2))
            .max_header_list_size(MAX_HTTP_RESPONSE_HEAD as u32)
            .handshake(stream),
    )
    .await
    .map_err(|_| phase_timeout("HTTP/2 probe startup timed out"))?
    .map_err(|error| anyhow::Error::new(error).context("HTTP/2 probe startup failed"))?;
    let rounds = async {
        let warm = if cold {
            None
        } else {
            let (warm, status) = tokio::time::timeout(
                timeout,
                h2_round(&mut sender, request, http::Method::HEAD, reporter, true),
            )
            .await
            .map_err(|_| phase_timeout("HTTP probe warm-up request timed out"))?
            .map_err(RoundError::into_error)?;
            validate_status_code(status)?;
            Some(warm)
        };
        match tokio::time::timeout(
            timeout,
            h2_round(
                &mut sender,
                request,
                request.method().clone(),
                reporter,
                false,
            ),
        )
        .await
        {
            Ok(Ok((measured, status))) => {
                validate_status_code(status)?;
                if let Some(reporter) = reporter {
                    reporter.probe_latency(measured.latency);
                }
                Ok(measured)
            }
            Ok(Err(RoundError::Transport(error))) => warm.ok_or(error),
            Err(_) => warm.ok_or_else(|| phase_timeout("HTTP probe request timed out")),
            Ok(Err(RoundError::Invalid(error))) => Err(error),
        }
    };
    tokio::pin!(rounds);
    tokio::select! {
        result = &mut rounds => result,
        _ = connection => rounds.await,
    }
}

fn http1_wire_request(
    request: &http::Request<()>,
    method: &http::Method,
    close: bool,
) -> anyhow::Result<String> {
    let target = request_target(request)?;
    Ok(format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: honk-http-probe/1.0\r\n{}\r\n",
        method,
        target.request_target(),
        target.authority(),
        if close { "Connection: close\r\n" } else { "" }
    ))
}

pub(super) const MAX_HTTP_RESPONSE_HEAD: usize = 16 * 1024;

async fn read_response_head<S>(
    stream: &mut S,
    reporter: &Option<ScoreReporter>,
    first_response: bool,
    response_started: &mut bool,
) -> Result<http::StatusCode, RoundError>
where
    S: AsyncBufRead + Unpin,
{
    let mut head = Vec::with_capacity(1024);
    let mut total = 0;
    loop {
        if total == MAX_HTTP_RESPONSE_HEAD {
            return Err(RoundError::Invalid(anyhow!(
                "HTTP response heads exceed {MAX_HTTP_RESPONSE_HEAD} bytes"
            )));
        }
        let first_bytes = !*response_started;
        let (consumed, complete) = {
            let available = match stream.fill_buf().await {
                Ok(available) => available,
                Err(error) if !*response_started => {
                    return Err(RoundError::Transport(
                        anyhow::Error::new(error).context("HTTP probe read failed"),
                    ));
                }
                Err(error) => {
                    return Err(RoundError::Invalid(
                        anyhow::Error::new(error).context("truncated HTTP response head"),
                    ));
                }
            };
            if available.is_empty() {
                return if !*response_started {
                    Err(RoundError::Transport(anyhow!(
                        "connection closed without an HTTP response"
                    )))
                } else {
                    Err(RoundError::Invalid(anyhow!("truncated HTTP response head")))
                };
            }
            *response_started = true;
            let take = available.len().min(MAX_HTTP_RESPONSE_HEAD - total);
            let old_len = head.len();
            head.extend_from_slice(&available[..take]);
            let scan_from = old_len.saturating_sub(3);
            let complete = head[scan_from..]
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .map(|offset| scan_from + offset + 4);
            let consumed = complete.map_or(take, |end| end - old_len);
            (consumed, complete)
        };
        stream.consume(consumed);
        total += consumed;
        if first_response && first_bytes {
            reporter_first_response(reporter);
        }
        reporter_rx(reporter, consumed);
        if let Some(end) = complete {
            head.truncate(end);
            let status = validate_response_head(&head).map_err(RoundError::Invalid)?;
            if !status.is_informational() || status == http::StatusCode::SWITCHING_PROTOCOLS {
                return Ok(status);
            }
            head.clear();
        }
    }
}

async fn http1_round<S>(
    stream: &mut S,
    request: &http::Request<()>,
    method: &http::Method,
    close: bool,
    reporter: &Option<ScoreReporter>,
    first_response: bool,
    timeout: Duration,
) -> Result<(ProbeMeasurement, http::StatusCode), RoundError>
where
    S: AsyncBufRead + AsyncWrite + Unpin,
{
    let wire = http1_wire_request(request, method, close).map_err(RoundError::Invalid)?;
    let mut response_started = false;
    let round = async {
        let start = Instant::now();
        stream.write_all(wire.as_bytes()).await.map_err(|error| {
            RoundError::Transport(anyhow::Error::new(error).context("HTTP probe write failed"))
        })?;
        reporter_tx(reporter, wire.len());
        let status =
            read_response_head(stream, reporter, first_response, &mut response_started).await?;
        Ok((
            ProbeMeasurement {
                latency: start.elapsed(),
                observed_at: SystemTime::now(),
            },
            status,
        ))
    };
    match tokio::time::timeout(timeout, round).await {
        Ok(result) => result,
        Err(_) => {
            let error = phase_timeout("HTTP probe request timed out");
            if response_started {
                Err(RoundError::Invalid(
                    error.context("incomplete HTTP response head"),
                ))
            } else {
                Err(RoundError::Transport(error))
            }
        }
    }
}

/// Cold or warmed HTTP/1.x requests. Only measured-round transport failure
/// may fall back to a validated warm response.
pub(super) async fn exchange_http1<S>(
    stream: &mut S,
    request: &http::Request<()>,
    reporter: &Option<ScoreReporter>,
    timeout: Duration,
    cold: bool,
) -> anyhow::Result<ProbeMeasurement>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut stream = BufReader::new(stream);
    let warm = if cold {
        None
    } else {
        let (warm, status) = http1_round(
            &mut stream,
            request,
            &http::Method::HEAD,
            false,
            reporter,
            true,
            timeout,
        )
        .await
        .map_err(RoundError::into_error)?;
        validate_status_code(status)?;
        Some(warm)
    };
    match http1_round(
        &mut stream,
        request,
        request.method(),
        true,
        reporter,
        false,
        timeout,
    )
    .await
    {
        Ok((measured, status)) => {
            validate_status_code(status)?;
            if let Some(reporter) = reporter {
                reporter.probe_latency(measured.latency);
            }
            Ok(measured)
        }
        Err(RoundError::Transport(error)) => warm.ok_or(error),
        Err(RoundError::Invalid(error)) => Err(error),
    }
}

fn validate_status_code(status: http::StatusCode) -> anyhow::Result<()> {
    if (200..500).contains(&status.as_u16()) {
        Ok(())
    } else {
        Err(anyhow!("bad status code: {status}"))
    }
}

fn validate_response_head(head: &[u8]) -> anyhow::Result<http::StatusCode> {
    if head.len() > MAX_HTTP_RESPONSE_HEAD || !head.ends_with(b"\r\n\r\n") {
        return Err(anyhow!("incomplete HTTP response head"));
    }
    let mut lines = head[..head.len() - 2].split(|byte| *byte == b'\n');
    let status = lines
        .next()
        .and_then(|line| line.strip_suffix(b"\r"))
        .ok_or_else(|| anyhow!("malformed HTTP status line"))?;
    let separator = status
        .iter()
        .position(|byte| *byte == b' ')
        .ok_or_else(|| anyhow!("malformed HTTP status line"))?;
    let version = &status[..separator];
    if version != b"HTTP/1.0" && version != b"HTTP/1.1" {
        return Err(anyhow!("unsupported HTTP response version"));
    }
    let remainder = &status[separator + 1..];
    let code_end = remainder
        .iter()
        .position(|byte| *byte == b' ')
        .unwrap_or(remainder.len());
    let code = &remainder[..code_end];
    if code.len() != 3 || !code.iter().all(u8::is_ascii_digit) {
        return Err(anyhow!("malformed HTTP status code"));
    }
    if remainder[code_end..]
        .iter()
        .any(|byte| (*byte < b' ' && *byte != b'\t') || *byte == 0x7f)
    {
        return Err(anyhow!("malformed HTTP reason phrase"));
    }
    let status = http::StatusCode::from_bytes(code).context("invalid HTTP status code")?;

    for raw_line in lines {
        if raw_line.is_empty() {
            continue;
        }
        let line = raw_line
            .strip_suffix(b"\r")
            .ok_or_else(|| anyhow!("malformed HTTP header line ending"))?;
        let colon = line
            .iter()
            .position(|byte| *byte == b':')
            .ok_or_else(|| anyhow!("malformed HTTP response header"))?;
        let name = &line[..colon];
        if name.is_empty() || !name.iter().copied().all(is_header_name_byte) {
            return Err(anyhow!("malformed HTTP response header name"));
        }
        if line[colon + 1..]
            .iter()
            .any(|byte| (*byte < b' ' && *byte != b'\t') || *byte == 0x7f)
        {
            return Err(anyhow!("malformed HTTP response header value"));
        }
    }
    Ok(status)
}

fn is_header_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}
