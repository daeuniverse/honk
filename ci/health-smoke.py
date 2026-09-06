#!/usr/bin/env python3
"""Run with HONK_CORE_BIN set; require real startup health requests over SOCKS5."""

import contextlib
import os
import socket
import socketserver
import subprocess
import tempfile
import threading
from pathlib import Path

observed = threading.Event()


class SocksHealthServer(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(2)
        try:
            greeting = self.rfile.read(2)
            if len(greeting) != 2 or greeting[0] != 5:
                return
            self.rfile.read(greeting[1])
            self.wfile.write(b'\x05\x00')
            request = self.rfile.read(4)
            if len(request) != 4 or request[:2] != b'\x05\x01':
                return
            size = {1: 4, 4: 16}.get(request[3])
            if request[3] == 3:
                size = self.rfile.read(1)[0]
            if size is None or len(self.rfile.read(size + 2)) != size + 2:
                return
            self.wfile.write(b'\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x09')
            for exchange in range(2):
                first = self.rfile.readline(8192)
                if not first:
                    return
                while self.rfile.readline(8192) not in (b'\r\n', b''):
                    pass
                self.wfile.write(b'HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n')
                if exchange == 1 and first.split()[1:2] == [b'/honk-health-proof']:
                    observed.set()
        except (OSError, IndexError):
            pass


with tempfile.TemporaryDirectory(prefix='honk-health-proof-') as directory:
    work = Path(directory)
    with socketserver.ThreadingTCPServer(('127.0.0.1', 0), SocksHealthServer) as server, contextlib.ExitStack() as cleanup:
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        cleanup.callback(thread.join)
        cleanup.callback(server.shutdown)
        with socket.socket() as reservation:
            reservation.bind(('0.0.0.0', 0))
            tproxy_port = reservation.getsockname()[1]
        config = work / 'health.dae'
        config.write_text(f'''global {{
 tproxy_port: {tproxy_port}
 data_dir: '{work}'
 nfqueue_enable: false
 check_interval: 86400s
 tcp_check_url: 'http://127.0.0.1:9/honk-health-proof'
 udp_check_dns: '127.0.0.1:9'
 udp_warm_node_count: 0
}}
node {{
 probe: 'socks5://127.0.0.1:{server.server_address[1]}#probe'
}}
group {{
 probes {{
  policy: fallback
  filter: name(probe)
 }}
}}
routing {{
 fallback: probes
}}
experimental {{
 clash_api {{
  enabled: false
 }}
}}
''')
        with (work / 'process.log').open('w+b') as output:
            environment = dict(os.environ, RUST_LOG='info', HONK_POOL_DISABLE='1')
            process = subprocess.Popen([os.environ['HONK_CORE_BIN'], '--config', str(config), '--mock-ebpf'], stdout=output, stderr=subprocess.STDOUT, env=environment)
            try:
                if not observed.wait(8):
                    output.seek(0, os.SEEK_END)
                    output.seek(max(0, output.tell() - 16384))
                    raise AssertionError('no completed two-request health probe observed\n' + output.read().decode(errors='replace'))
                print('health-smoke: PASS (startup scheduler sent both proxied HTTP health requests)')
            finally:
                process.terminate()
                try:
                    process.wait(10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
