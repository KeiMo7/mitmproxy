"""
End-to-end demonstration of session-context replay.

Run with::

    uv run python examples/addons/session-replay-demo.py

The script starts a local HTTP server whose responses depend on the session
context (connection reuse and cookies), captures a session against it, and then
replays that capture. It prints:

1. the response differences between the original and the replayed session,
2. the exact request at which the two diverge,
3. full-context replay vs. degraded replay, and
4. whether replaying the same capture three times is stable.

It is fully self-contained and does not require network access.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import AsyncIterator

from mitmproxy import http
from mitmproxy.addons.proxyserver import Proxyserver
from mitmproxy.addons.sessionplayback import SessionPlayback
from mitmproxy.test import taddons
from mitmproxy.test import tflow
from mitmproxy.test import tutils

Addr = tuple[str, int]


@contextlib.asynccontextmanager
async def server(handler) -> AsyncIterator[Addr]:
    tasks = asyncio.TaskGroup()

    async def wrapper(reader, writer):
        try:
            await handler(reader, writer)
        finally:
            if not writer.is_closing():
                writer.close()
            await writer.wait_closed()

    def accept(reader, writer):
        tasks.create_task(wrapper(reader, writer))

    srv = await asyncio.start_server(accept, "127.0.0.1", 0)
    async with srv:
        async with tasks:
            sock = srv.sockets[0].getsockname()
            yield sock[0], sock[1]


class StatefulServer:
    """The server behaves differently depending on cookies and connection reuse."""

    def __init__(self) -> None:
        self.requests_per_connection: dict[int, int] = {}

    async def handle(self, reader, writer) -> None:
        connection_id = id(writer)
        while True:
            line = await reader.readline()
            if not line:
                break
            headers: dict[bytes, bytes] = {}
            while True:
                header = await reader.readline()
                if header in (b"\r\n", b""):
                    break
                name, _, value = header.partition(b":")
                headers[name.strip().lower()] = value.strip()
            self.requests_per_connection[connection_id] = (
                self.requests_per_connection.get(connection_id, 0) + 1
            )
            count = self.requests_per_connection[connection_id]
            cookie = headers.get(b"cookie", b"")
            if b"session=logged-in" in cookie:
                body = f"welcome (request {count} on this connection)".encode()
            else:
                body = b"please log in"
            writer.write(
                b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s" % (len(body), body)
            )
            await writer.drain()


def make_flow(addr: Addr, path: str, *, start: float, cookie: str) -> http.HTTPFlow:
    """Create a request-only flow; the response is filled in by `capture`."""
    host, port = addr
    flow = tflow.tflow(
        req=tutils.treq(host=host, port=port, method=b"GET", path=path.encode()),
        live=False,
    )
    flow.request.host, flow.request.port = addr
    flow.request.scheme = "http"
    flow.request.host_header = f"example.com:{port}"
    flow.request.raw_content = b""
    flow.request.headers["cookie"] = cookie
    flow.request.timestamp_start = start
    flow.request.timestamp_end = start + 0.01
    flow.server_conn.id = "session-connection"
    flow.server_conn.address = addr
    return flow


async def capture(addr: Addr, requests: list[tuple[str, str]]) -> list[http.HTTPFlow]:
    """
    Send the requests on one connection, exactly like the original client, and
    record the responses. This is our "captured session".
    """
    flows = []
    reader, writer = await asyncio.open_connection(*addr)
    try:
        for i, (path, cookie) in enumerate(requests):
            flow = make_flow(addr, path, start=1000.0 + i, cookie=cookie)
            writer.write(
                f"GET {path} HTTP/1.1\r\nHost: example.com\r\n"
                f"Cookie: {cookie}\r\n\r\n".encode()
            )
            await writer.drain()
            status_line = await reader.readline()
            status = int(status_line.split()[1])
            headers: dict[str, str] = {}
            while True:
                header = await reader.readline()
                if header in (b"\r\n", b""):
                    break
                name, _, value = header.decode().partition(":")
                headers[name.strip().lower()] = value.strip()
            body = await reader.readexactly(int(headers["content-length"]))
            flow.response = http.Response.make(status, body, headers)
            flow.response.timestamp_start = 1000.0 + i + 0.02
            flow.response.timestamp_end = 1000.0 + i + 0.03
            flows.append(flow)
    finally:
        writer.close()
        await writer.wait_closed()
    return flows


async def replay(
    flows: list[http.HTTPFlow], *, runs: int = 1
) -> tuple[str, SessionPlayback]:
    cp = SessionPlayback()
    with taddons.context(cp, Proxyserver()) as tctx:
        tctx.configure(cp, session_replay_runs=runs)
        cp.start_replay(flows)
        while cp._busy or not cp.reports:
            await asyncio.sleep(0.01)
        return cp.report(), cp


def main() -> None:
    asyncio.run(_main())


async def _main() -> None:
    stateful = StatefulServer()
    async with server(stateful.handle) as addr:
        requests = [
            ("/login", "session=anonymous"),
            ("/me", "session=logged-in; stage=1"),
            ("/cart", "session=logged-in; stage=2"),
        ]
        captured = await capture(addr, requests)

        print("=" * 72)
        print("Original captured session")
        print("=" * 72)
        for flow in captured:
            assert flow.response
            print(
                f"  {flow.request.method} {flow.request.path} "
                f"cookie={flow.request.headers['cookie']!r} -> "
                f"{flow.response.status_code} {flow.response.text!r}"
            )

        print()
        print("=" * 72)
        print("1. Full-context replay (one connection, capture-time cookies)")
        print("=" * 72)
        text, cp = await replay(captured, runs=3)
        print(text)
        assert cp.stability is not None
        print(
            "\nStability:",
            "stable across 3 runs"
            if cp.stability.stable
            else "NOT stable: " + "; ".join(cp.stability.details),
        )

        print()
        print("=" * 72)
        print("2. Degraded replay: the capture lost the per-request cookie chain")
        print("=" * 72)
        from mitmproxy import session as session_context

        # Simulate the classic bug: all requests are replayed with the *latest*
        # cookie instead of the cookie that was valid at the time.
        latest_cookie = captured[-1].request.headers["cookie"]
        degraded_flows = []
        for flow in captured:
            copy = flow.copy()
            copy.request.headers["cookie"] = latest_cookie
            # Also simulate missing TLS context: an upstream TLS connection
            # without a captured session ticket.
            copy.server_conn.tls = True
            copy.server_conn.cipher = "TLS_AES_256_GCM_SHA384"
            degraded_flows.append(copy)
        session_context.capture_context(degraded_flows[0], session_ticket=b"ticket")
        text, degraded_cp = await replay(degraded_flows)
        print(text)
        assert degraded_cp.session is not None
        print("\nSession mode:", degraded_cp.session.mode)
        print("Replay report mode:", degraded_cp.reports[0].mode)


if __name__ == "__main__":
    main()
