#!/usr/bin/env python3
"""Unprivileged actual-process smoke for honk-core's standalone DNS listener."""

from __future__ import annotations

import collections
import os
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import BinaryIO

LOOPBACK = "127.0.0.1"
ANSWER = bytes((192, 0, 2, 123))
DNS_TIMEOUT = 3.0
START_TIMEOUT = 20.0
RELOAD_TIMEOUT = 20.0
SHUTDOWN_TIMEOUT = 30.0
BUILD_TIMEOUT = 900.0
MAX_FAILURE_OUTPUT = 16 * 1024
MAX_CAPTURED_LINES = 80


class SmokeFailure(RuntimeError):
    """A concise failure suitable for command-line reporting."""

    def __init__(self, message: str, output: str = "") -> None:
        super().__init__(message)
        self.output = output


def _tail_bytes(stream: BinaryIO, limit: int = MAX_FAILURE_OUTPUT) -> str:
    stream.flush()
    size = stream.seek(0, os.SEEK_END)
    stream.seek(max(0, size - limit))
    return stream.read(limit).decode("utf-8", errors="replace").strip()


def _cargo_target_dir(project_root: Path) -> Path:
    configured = os.environ.get("CARGO_TARGET_DIR")
    if not configured:
        return project_root / "target"
    path = Path(configured).expanduser()
    return path if path.is_absolute() else project_root / path


def _build_debug_binary(project_root: Path) -> Path:
    configured_binary = os.environ.get("HONK_CORE_BIN")
    if configured_binary:
        binary = Path(configured_binary).expanduser().resolve()
        if not binary.is_file() or not os.access(binary, os.X_OK):
            raise SmokeFailure(f"HONK_CORE_BIN is not an executable file: {binary}")
        return binary

    binary = _cargo_target_dir(project_root) / "debug" / "honk-core"
    with tempfile.TemporaryFile(mode="w+b") as output:
        try:
            result = subprocess.run(
                ["cargo", "build", "-p", "honk-core", "--bin", "honk-core"],
                cwd=project_root,
                stdin=subprocess.DEVNULL,
                stdout=output,
                stderr=subprocess.STDOUT,
                timeout=BUILD_TIMEOUT,
                check=False,
            )
        except FileNotFoundError as error:
            raise SmokeFailure("cargo was not found in PATH") from error
        except subprocess.TimeoutExpired as error:
            raise SmokeFailure(
                f"debug honk-core build exceeded {BUILD_TIMEOUT:.0f}s",
                _tail_bytes(output),
            ) from error
        if result.returncode != 0:
            raise SmokeFailure(
                f"debug honk-core build exited with status {result.returncode}",
                _tail_bytes(output),
            )
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise SmokeFailure(f"cargo did not produce an executable at {binary}")
    return binary


class PortReservation:
    """Reserve one dynamically selected TCP+UDP port until process launch."""

    def __init__(self, host: str) -> None:
        self.tcp: socket.socket | None = None
        self.udp: socket.socket | None = None
        self.port = 0
        for _ in range(64):
            tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                tcp.bind((host, 0))
                port = tcp.getsockname()[1]
                if port < 1024:
                    tcp.close()
                    udp.close()
                    continue
                udp.bind((host, port))
                tcp.listen(1)
            except OSError:
                tcp.close()
                udp.close()
                continue
            self.tcp = tcp
            self.udp = udp
            self.port = port
            return
        raise SmokeFailure(f"could not reserve a nonprivileged TCP+UDP port on {host}")

    def close(self) -> None:
        if self.tcp is not None:
            self.tcp.close()
            self.tcp = None
        if self.udp is not None:
            self.udp.close()
            self.udp = None


def _decode_name(message: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    cursor = offset
    next_offset: int | None = None
    visited: set[int] = set()
    while True:
        if cursor >= len(message):
            raise SmokeFailure("truncated DNS name")
        length = message[cursor]
        if length & 0xC0 == 0xC0:
            if cursor + 1 >= len(message):
                raise SmokeFailure("truncated DNS compression pointer")
            pointer = ((length & 0x3F) << 8) | message[cursor + 1]
            if pointer in visited or pointer >= len(message):
                raise SmokeFailure("invalid DNS compression pointer")
            visited.add(pointer)
            if next_offset is None:
                next_offset = cursor + 2
            cursor = pointer
            continue
        if length & 0xC0:
            raise SmokeFailure("invalid DNS label length")
        cursor += 1
        if length == 0:
            end = next_offset if next_offset is not None else cursor
            return (".".join(labels) + "." if labels else ".", end)
        if length > 63 or cursor + length > len(message):
            raise SmokeFailure("truncated DNS label")
        try:
            labels.append(message[cursor : cursor + length].decode("ascii").lower())
        except UnicodeDecodeError as error:
            raise SmokeFailure("non-ASCII DNS name in smoke exchange") from error
        cursor += length


def _question(message: bytes) -> tuple[str, int, int, int]:
    if len(message) < 12:
        raise SmokeFailure("DNS message is shorter than its header")
    if struct.unpack_from("!H", message, 4)[0] != 1:
        raise SmokeFailure("smoke DNS message does not contain exactly one question")
    name, offset = _decode_name(message, 12)
    if offset + 4 > len(message):
        raise SmokeFailure("truncated DNS question")
    qtype, qclass = struct.unpack_from("!HH", message, offset)
    return name, qtype, qclass, offset + 4


def _make_query(txid: int, name: str) -> bytes:
    labels = name.rstrip(".").split(".")
    qname = bytearray()
    for label in labels:
        encoded = label.encode("ascii")
        if not encoded or len(encoded) > 63:
            raise SmokeFailure(f"invalid smoke query label {label!r}")
        qname.append(len(encoded))
        qname.extend(encoded)
    qname.append(0)
    return (
        struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
        + bytes(qname)
        + struct.pack("!HH", 1, 1)
    )


def _make_answer(query: bytes) -> bytes:
    name, qtype, qclass, question_end = _question(query)
    if query[2] & 0x80 or qtype != 1 or qclass != 1 or not name.endswith(".smoke.test."):
        raise SmokeFailure(f"unexpected upstream query for {name} type {qtype} class {qclass}")
    return (
        query[:2]
        + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0)
        + query[12:question_end]
        + b"\xc0\x0c"
        + struct.pack("!HHIH", 1, 1, 60, len(ANSWER))
        + ANSWER
    )


def _validate_answer(query: bytes, response: bytes) -> None:
    if len(response) < 12:
        raise SmokeFailure("DNS response is shorter than its header")
    expected_txid = query[:2]
    if response[:2] != expected_txid:
        raise SmokeFailure(
            f"DNS transaction ID mismatch: expected {expected_txid.hex()}, got {response[:2].hex()}"
        )
    expected = _make_answer(query)
    if response[2:] != expected[2:]:
        raise SmokeFailure("DNS response answer bytes differ from the deterministic upstream")

    flags, qdcount, ancount, nscount, arcount = struct.unpack_from("!HHHHH", response, 2)
    if flags & 0x8000 == 0 or flags & 0x000F != 0:
        raise SmokeFailure(f"DNS response has unexpected flags 0x{flags:04x}")
    if (qdcount, ancount, nscount, arcount) != (1, 1, 0, 0):
        raise SmokeFailure("DNS response has unexpected section counts")
    name, qtype, qclass, offset = _question(response)
    expected_name, _, _, _ = _question(query)
    if (name, qtype, qclass) != (expected_name, 1, 1):
        raise SmokeFailure("DNS response question differs from the query")
    _, offset = _decode_name(response, offset)
    if offset + 10 > len(response):
        raise SmokeFailure("truncated DNS answer record")
    atype, aclass, ttl, length = struct.unpack_from("!HHIH", response, offset)
    offset += 10
    if (atype, aclass, ttl, length) != (1, 1, 60, len(ANSWER)):
        raise SmokeFailure("DNS response has unexpected answer metadata")
    if response[offset : offset + length] != ANSWER or offset + length != len(response):
        raise SmokeFailure("DNS response has unexpected A-record bytes")


class DeterministicUdpDns:
    """Small local UDP authority used as the only configured upstream."""

    def __init__(self) -> None:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((LOOPBACK, 0))
        self.socket.settimeout(0.1)
        self.port = self.socket.getsockname()[1]
        if self.port < 1024:
            self.socket.close()
            raise SmokeFailure("kernel selected a privileged upstream port")
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._errors: list[str] = []
        self._queries: list[str] = []
        self._thread = threading.Thread(target=self._serve, name="dns-smoke-upstream")
        self._thread.start()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                query, peer = self.socket.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError as error:
                if not self._stop.is_set():
                    with self._lock:
                        self._errors.append(f"upstream receive failed: {error}")
                return
            try:
                answer = _make_answer(query)
                name, _, _, _ = _question(query)
                with self._lock:
                    self._queries.append(name)
                self.socket.sendto(answer, peer)
            except (OSError, SmokeFailure) as error:
                with self._lock:
                    self._errors.append(str(error))

    def assert_queries(self, expected: list[str]) -> None:
        with self._lock:
            errors = list(self._errors)
            queries = list(self._queries)
        if errors:
            raise SmokeFailure("local DNS upstream failed: " + "; ".join(errors))
        if queries != expected:
            raise SmokeFailure(f"local DNS upstream saw {queries!r}, expected {expected!r}")

    def close(self) -> None:
        self._stop.set()
        self.socket.close()
        self._thread.join(timeout=2.0)
        if self._thread.is_alive():
            raise SmokeFailure("local DNS upstream thread did not stop")


class ProcessOutput:
    """Continuously drain output while retaining only a bounded diagnostic tail."""

    def __init__(self, stream: BinaryIO) -> None:
        self._stream = stream
        self._lines: collections.deque[str] = collections.deque(maxlen=MAX_CAPTURED_LINES)
        self._lock = threading.Lock()
        self.ready = threading.Event()
        self.reloaded = threading.Event()
        self._thread = threading.Thread(target=self._drain, name="dns-smoke-output")
        self._thread.start()

    def _drain(self) -> None:
        for raw_line in iter(self._stream.readline, b""):
            line = raw_line.decode("utf-8", errors="replace").rstrip("\r\n")
            with self._lock:
                self._lines.append(line[:2048])
            if "Standalone DNS listener started" in line:
                self.ready.set()
            if "SIGHUP reload request 1 applied" in line:
                self.reloaded.set()

    def wait_for(self, event: threading.Event, process: subprocess.Popen[bytes], timeout: float, what: str) -> None:
        deadline = time.monotonic() + timeout
        while not event.is_set():
            status = process.poll()
            if status is not None:
                raise SmokeFailure(f"honk-core exited with status {status} while waiting for {what}")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise SmokeFailure(f"timed out waiting for {what}")
            event.wait(min(0.05, remaining))

    def close(self) -> None:
        self._thread.join(timeout=2.0)

    def tail(self) -> str:
        with self._lock:
            text = "\n".join(self._lines)
        return text[-MAX_FAILURE_OUTPUT:].strip()


def _recv_exact(stream: socket.socket, length: int) -> bytes:
    chunks: list[bytes] = []
    remaining = length
    while remaining:
        chunk = stream.recv(remaining)
        if not chunk:
            raise SmokeFailure("TCP DNS connection closed before the complete frame arrived")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _tcp_exchange(stream: socket.socket, query: bytes) -> bytes:
    if len(query) > 65535:
        raise SmokeFailure("smoke DNS query is too large for RFC 7766 framing")
    stream.sendall(struct.pack("!H", len(query)) + query)
    length = struct.unpack("!H", _recv_exact(stream, 2))[0]
    if length == 0:
        raise SmokeFailure("TCP DNS response used an empty RFC 7766 frame")
    return _recv_exact(stream, length)


def _udp_exchange(port: int, query: bytes) -> bytes:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(DNS_TIMEOUT)
        client.sendto(query, (LOOPBACK, port))
        response, source = client.recvfrom(65535)
    if source != (LOOPBACK, port):
        raise SmokeFailure(f"UDP DNS response came from unexpected source {source!r}")
    return response


def _write_config(path: Path, dns_port: int, tproxy_port: int, upstream_port: int) -> None:
    path.write_text(
        f"""global {{
    tproxy_port: {tproxy_port}
    tproxy_port_protect: false
    log_level: info
    disable_waiting_network: true
    auto_config_kernel_parameter: false
    nfqueue_enable: false
    store_subscribe: false
    tcp_check_url: 'http://127.0.0.1:{upstream_port}'
    udp_check_dns: '127.0.0.1:{upstream_port}'
    fallback_resolver: '127.0.0.1:{upstream_port}'
    check_interval: 86400s
    preconnect_node_count: 0
    udp_warm_node_count: 0
}}

dns {{
    bind: 'tcp+udp://127.0.0.1:{dns_port}'
    optimistic_cache: false
    upstream {{
        smoke: 'udp://127.0.0.1:{upstream_port}'
    }}
    routing {{
        request {{
            fallback: smoke
        }}
    }}
}}

routing {{
    fallback: direct
}}
""",
        encoding="utf-8",
    )


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=5.0)
    except subprocess.TimeoutExpired as error:
        raise SmokeFailure("honk-core process group survived SIGKILL") from error


def _cleanup_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        process.send_signal(signal.SIGTERM)
        process.wait(timeout=SHUTDOWN_TIMEOUT)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        _kill_process_group(process)


def _run_smoke(project_root: Path) -> None:
    binary = _build_debug_binary(project_root)
    capture: ProcessOutput | None = None
    process: subprocess.Popen[bytes] | None = None
    upstream: DeterministicUdpDns | None = None
    dns_reservation: PortReservation | None = None
    tproxy_reservation: PortReservation | None = None
    temporary: tempfile.TemporaryDirectory[str] | None = None
    primary_error: BaseException | None = None

    try:
        temporary = tempfile.TemporaryDirectory(prefix="honk-dns-smoke-")
        workdir = Path(temporary.name)
        pin_root = workdir / "bpf"
        pin_root.mkdir()
        config_path = workdir / "smoke.dae"

        upstream = DeterministicUdpDns()
        dns_reservation = PortReservation(LOOPBACK)
        tproxy_reservation = PortReservation("0.0.0.0")
        _write_config(
            config_path,
            dns_reservation.port,
            tproxy_reservation.port,
            upstream.port,
        )
        dns_port = dns_reservation.port
        dns_reservation.close()
        tproxy_reservation.close()

        environment = os.environ.copy()
        environment["RUST_LOG"] = "info"
        process = subprocess.Popen(
            [
                str(binary),
                "--config",
                str(config_path),
                "--bpf-pin-root",
                str(pin_root),
                "--mock-ebpf",
            ],
            cwd=workdir,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        if process.stdout is None:
            raise SmokeFailure("could not capture honk-core output")
        capture = ProcessOutput(process.stdout)
        capture.wait_for(capture.ready, process, START_TIMEOUT, "the standalone DNS listener")

        expected_queries: list[str] = []
        udp_query = _make_query(0x1001, "udp.smoke.test")
        _validate_answer(udp_query, _udp_exchange(dns_port, udp_query))
        expected_queries.append("udp.smoke.test.")

        with socket.create_connection((LOOPBACK, dns_port), timeout=DNS_TIMEOUT) as tcp:
            tcp.settimeout(DNS_TIMEOUT)
            first = _make_query(0x2001, "tcp-one.smoke.test")
            _validate_answer(first, _tcp_exchange(tcp, first))
            expected_queries.append("tcp-one.smoke.test.")

            second = _make_query(0x2002, "tcp-two.smoke.test")
            _validate_answer(second, _tcp_exchange(tcp, second))
            expected_queries.append("tcp-two.smoke.test.")

        process.send_signal(signal.SIGHUP)
        capture.wait_for(capture.reloaded, process, RELOAD_TIMEOUT, "unchanged SIGHUP reload")

        reload_query = _make_query(0x3001, "reload.smoke.test")
        _validate_answer(reload_query, _udp_exchange(dns_port, reload_query))
        expected_queries.append("reload.smoke.test.")
        upstream.assert_queries(expected_queries)

        process.send_signal(signal.SIGTERM)
        try:
            status = process.wait(timeout=SHUTDOWN_TIMEOUT)
        except subprocess.TimeoutExpired as error:
            _kill_process_group(process)
            raise SmokeFailure(
                f"honk-core did not exit within {SHUTDOWN_TIMEOUT:.0f}s after SIGTERM"
            ) from error
        if status != 0:
            raise SmokeFailure(f"honk-core exited with status {status} after SIGTERM")
    except BaseException as error:
        primary_error = error
    finally:
        cleanup_errors: list[str] = []
        if process is not None:
            try:
                _cleanup_process(process)
            except SmokeFailure as error:
                cleanup_errors.append(str(error))
        if capture is not None:
            capture.close()
        if upstream is not None:
            try:
                upstream.close()
            except SmokeFailure as error:
                cleanup_errors.append(str(error))
        if dns_reservation is not None:
            dns_reservation.close()
        if tproxy_reservation is not None:
            tproxy_reservation.close()
        if temporary is not None:
            try:
                temporary.cleanup()
            except OSError as error:
                cleanup_errors.append(f"temporary directory cleanup failed: {error}")

        if primary_error is not None:
            if isinstance(primary_error, SmokeFailure):
                output = primary_error.output or (capture.tail() if capture is not None else "")
                message = str(primary_error)
            else:
                output = capture.tail() if capture is not None else ""
                message = f"{type(primary_error).__name__}: {primary_error}"
            if cleanup_errors:
                message += "; cleanup: " + "; ".join(cleanup_errors)
            raise SmokeFailure(message, output) from primary_error
        if cleanup_errors:
            raise SmokeFailure("; ".join(cleanup_errors), capture.tail() if capture is not None else "")


def main() -> int:
    project_root = Path(__file__).resolve().parents[1]
    try:
        _run_smoke(project_root)
    except SmokeFailure as error:
        print(f"dns-smoke: FAIL: {error}", file=sys.stderr)
        if error.output:
            print("--- bounded local process output ---", file=sys.stderr)
            print(error.output[-MAX_FAILURE_OUTPUT:], file=sys.stderr)
            print("--- end local process output ---", file=sys.stderr)
        return 1
    print("dns-smoke: PASS (UDP, persistent TCP, unchanged SIGHUP, clean shutdown)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
