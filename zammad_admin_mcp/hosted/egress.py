from __future__ import annotations

import asyncio
import base64
import secrets
import ipaddress
import socket
from collections.abc import Iterable
from urllib.parse import quote, urlsplit


class RestrictedEgressProxy:
    def __init__(self):
        self._server: asyncio.AbstractServer | None = None
        self._username = secrets.token_urlsafe(18)
        self._password = secrets.token_urlsafe(32)
        self._active_connections = 0

    @property
    def url(self) -> str:
        if self._server is None or not self._server.sockets:
            raise RuntimeError("Egress proxy is not running")
        host, port = self._server.sockets[0].getsockname()[:2]
        return f"http://{quote(self._username)}:{quote(self._password)}@{host}:{port}"

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0, limit=8192)

    async def close(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        upstream_writer: asyncio.StreamWriter | None = None
        self._active_connections += 1
        try:
            if self._active_connections > 64:
                writer.write(b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
                await writer.drain()
                return
            line = await asyncio.wait_for(reader.readline(), timeout=5)
            parts = line.decode("ascii").strip().split()
            if len(parts) != 3 or parts[0] != "CONNECT" or parts[2] != "HTTP/1.1":
                raise ValueError("Only HTTPS CONNECT is supported")
            host, separator, port_text = parts[1].rpartition(":")
            if not separator or not host or not port_text.isdecimal() or int(port_text) != 443:
                raise ValueError("Only HTTPS connections on port 443 are allowed")
            authorization = None
            while True:
                header = await asyncio.wait_for(reader.readline(), timeout=5)
                if header in (b"\r\n", b"\n"):
                    break
                if not header or len(header) > 4096:
                    raise ValueError("Invalid CONNECT request")
                name, separator, value = header.partition(b":")
                if separator and name.strip().lower() == b"proxy-authorization":
                    authorization = value.strip()
            expected = b"Basic " + base64.b64encode(f"{self._username}:{self._password}".encode())
            if not authorization or not secrets.compare_digest(authorization, expected):
                writer.write(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=restricted-egress\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
                await writer.drain()
                return
            target = host.strip("[]").encode("idna").decode("ascii")
            records = await asyncio.wait_for(
                asyncio.get_running_loop().getaddrinfo(target, 443, type=socket.SOCK_STREAM),
                timeout=10,
            )
            addresses = public_addresses(record[4][0] for record in records)
            last_error: OSError | None = None
            for address in sorted(addresses, key=lambda item: (item.version, int(item))):
                try:
                    upstream_reader, upstream_writer = await asyncio.wait_for(
                        asyncio.open_connection(str(address), 443), timeout=10
                    )
                    break
                except OSError as exc:
                    last_error = exc
            else:
                raise last_error or OSError("Destination connection failed")
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()
            await asyncio.gather(
                self._pipe(reader, upstream_writer),
                self._pipe(upstream_reader, writer),
            )
        except (ValueError, UnicodeError, OSError, asyncio.TimeoutError, asyncio.IncompleteReadError):
            writer.write(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            try:
                await writer.drain()
            except OSError:
                pass
        finally:
            self._active_connections -= 1
            if upstream_writer:
                upstream_writer.close()
                await upstream_writer.wait_closed()
            writer.close()
            await writer.wait_closed()

    @staticmethod
    async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        transferred = 0
        try:
            while chunk := await asyncio.wait_for(reader.read(65536), timeout=60):
                transferred += len(chunk)
                if transferred > 16 * 1024 * 1024:
                    return
                writer.write(chunk)
                await writer.drain()
        except ConnectionError:
            pass
        finally:
            try:
                writer.write_eof()
            except (AttributeError, OSError, RuntimeError):
                pass


def validate_public_mcp_url(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("MCP public URL must be HTTPS without credentials, query, or fragment")
    if parsed.port not in (None, 443) or parsed.path.rstrip("/") != "/mcp":
        raise ValueError("MCP public URL must use port 443 and end in /mcp")
    return f"https://{parsed.netloc}/mcp"


def validate_issuer_url(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("OAuth issuer must be HTTPS without credentials, query, or fragment")
    if parsed.port not in (None, 443):
        raise ValueError("OAuth issuer must use HTTPS port 443")
    return url.rstrip("/") + "/"


def public_addresses(values: Iterable[str]) -> set[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    addresses = {ipaddress.ip_address(value) for value in values}
    if not addresses or any(not address.is_global for address in addresses):
        raise ValueError("Destination does not resolve exclusively to public IP addresses")
    return addresses
