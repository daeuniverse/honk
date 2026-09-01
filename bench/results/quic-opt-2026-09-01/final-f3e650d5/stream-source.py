#!/usr/bin/env python3
import socket

address = ("198.18.0.2", 28080)
chunk = bytes(64 * 1024)
with socket.socket() as server:
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(address)
    server.listen()
    print("ready", flush=True)
    while True:
        connection, _ = server.accept()
        with connection:
            request = bytearray()
            while len(request) < 8:
                data = connection.recv(8 - len(request))
                if not data:
                    break
                request.extend(data)
            if len(request) != 8:
                continue
            remaining = int.from_bytes(request, "big")
            while remaining:
                sent = connection.send(chunk[: min(remaining, len(chunk))])
                if sent == 0:
                    break
                remaining -= sent
