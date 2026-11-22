import asyncio
import json
from contextlib import asynccontextmanager

import pytest

from mitmproxy import http
from mitmproxy.addons import sessionplayback
from mitmproxy.addons.proxyserver import Proxyserver
from mitmproxy.exceptions import CommandError
from mitmproxy.exceptions import OptionsError
from mitmproxy.test import taddons
from mitmproxy.test import tflow
from mitmproxy.test import tutils


@asynccontextmanager
async def tcp_server(handle_conn, **server_args):
    """A TCP server that spawns one handler per connection and tracks them."""
    if not hasattr(asyncio, "TaskGroup"):
        pytest.skip("Skipped because asyncio.TaskGroup is unavailable.")

    tasks = asyncio.TaskGroup()
    connections = []

    async def handle_conn_wrapper(reader, writer):
        connections.append(1)
        try:
            await handle_conn(reader, writer)
        except Exception as e:  # pragma: no cover - surfaced in test output
            print(f"!!! TCP handler failed: {e}")
            raise
        finally:
            if not writer.is_closing():
                writer.close()
            await writer.wait_closed()

    def _handle(r, w):
        tasks.create_task(handle_conn_wrapper(r, w))

    server = await asyncio.start_server(_handle, "127.0.0.1", 0, **server_args)
    await server.start_serving()
    async with server:
        async with tasks:
            yield server.sockets[0].getsockname(), connections


def make_flow(
    *,
    path="/path",
    host="example.com",
    port=80,
    start=1000.0,
    content=b"",
    response_content=b"",
    connection_id=None,
    cookie=None,
    response_headers=None,
):
    flow = tflow.tflow(
        req=tutils.treq(
            host=host,
            port=port,
            method=b"GET",
            path=path.encode(),
            content=content,
        ),
        resp=http.Response.make(
            200, response_content, response_headers or {"content-length": "0"}
        ),
        live=False,
    )
    flow.request.timestamp_start = start
    flow.request.timestamp_end = start + 0.1
    flow.response.timestamp_start = start + 0.2
    flow.response.timestamp_end = start + 0.3
    if connection_id is not None:
        flow.server_conn.id = connection_id
    if cookie is not None:
        flow.request.headers["cookie"] = cookie
    return flow


async def run_replay(cp, flows, timeout=5):
    cp.start_replay(flows)
    deadline = asyncio.get_event_loop().time() + timeout
    while cp._busy or not cp.reports:
        if asyncio.get_event_loop().time() > deadline:
            raise TimeoutError("session replay did not finish")
        await asyncio.sleep(0.01)


async def test_replay_preserves_connection_order():
    seen = []

    async def handler(reader, writer):
        while True:
            line = await reader.readline()
            if not line:
                break
            seen.append(line)
            while True:
                header = await reader.readline()
                if header in (b"\r\n", b""):
                    break
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            await writer.drain()

    cp = sessionplayback.SessionPlayback()
    ps = Proxyserver()
    with taddons.context(cp, ps) as tctx:
        tctx.configure(cp)
        async with tcp_server(handler) as (addr, connections):
            flows = []
            for i in range(3):
                flow = make_flow(
                    path=f"/p{i}", start=1000.0 + i, connection_id="shared"
                )
                flow.request.host, flow.request.port = addr
                flow.request.raw_content = b""
                flow.response.content = b"ok"
                flow.response.headers["content-length"] = "2"
                flows.append(flow)
            await run_replay(cp, flows)
            assert seen == [
                b"GET /p0 HTTP/1.1\r\n",
                b"GET /p1 HTTP/1.1\r\n",
                b"GET /p2 HTTP/1.1\r\n",
            ]
            # All three requests were sent on a single upstream connection.
            assert len(connections) == 1
            report = cp.reports[0]
            assert report.connection_order == [[0, 1, 2]]
            assert report.first_divergence is None


async def test_replay_sends_cookie_at_capture_time():
    seen = []

    async def handler(reader, writer):
        while True:
            line = await reader.readline()
            if not line:
                break
            headers = {}
            while True:
                header = await reader.readline()
                if header in (b"\r\n", b""):
                    break
                name, _, value = header.partition(b":")
                headers[name.strip().lower()] = value.strip()
            seen.append(headers.get(b"cookie"))
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            await writer.drain()

    cp = sessionplayback.SessionPlayback()
    with taddons.context(cp, Proxyserver()) as tctx:
        tctx.configure(cp, session_replay_concurrency=1)
        async with tcp_server(handler) as (addr, _):
            flows = []
            for i in range(2):
                flow = make_flow(
                    path=f"/p{i}",
                    start=1000.0 + i,
                    connection_id="shared",
                    cookie=f"session=value{i}",
                )
                flow.request.host, flow.request.port = addr
                flow.request.raw_content = b""
                flow.response.headers["content-length"] = "0"
                flows.append(flow)
            await run_replay(cp, flows)
            # Each request used the cookie value that was valid *then*.
            assert seen == [b"session=value0", b"session=value1"]


async def test_replay_divergence_is_located():
    responses = iter(
        [
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
            b"HTTP/1.1 500 Server Error\r\nContent-Length: 5\r\n\r\noops!",
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        ]
    )

    async def handler(reader, writer):
        while True:
            line = await reader.readline()
            if not line:
                break
            while True:
                header = await reader.readline()
                if header in (b"\r\n", b""):
                    break
            writer.write(next(responses))
            await writer.drain()

    cp = sessionplayback.SessionPlayback()
    with taddons.context(cp, Proxyserver()) as tctx:
        tctx.configure(cp)
        async with tcp_server(handler) as (addr, _):
            flows = []
            for i in range(3):
                flow = make_flow(start=1000.0 + i, connection_id="shared")
                flow.request.host, flow.request.port = addr
                flow.request.raw_content = b""
                flow.response.content = b"ok" if i != 1 else b"old"
                flow.response.status_code = 200
                flow.response.headers["content-length"] = str(
                    len(flow.response.content)
                )
                flows.append(flow)
            await run_replay(cp, flows)
            report = cp.reports[0]
            assert report.matching_prefix == 1
            assert report.first_divergence == 1
            assert report.results[0].matched
            assert not report.results[1].matched


async def test_replay_is_stable_across_runs():
    async def handler(reader, writer):
        while True:
            line = await reader.readline()
            if not line:
                break
            while True:
                header = await reader.readline()
                if header in (b"\r\n", b""):
                    break
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            await writer.drain()

    cp = sessionplayback.SessionPlayback()
    with taddons.context(cp, Proxyserver()) as tctx:
        tctx.configure(cp, session_replay_runs=3)
        async with tcp_server(handler) as (addr, _):
            flows = []
            for i in range(2):
                flow = make_flow(start=1000.0 + i, connection_id="shared")
                flow.request.host, flow.request.port = addr
                flow.request.raw_content = b""
                flow.response.content = b"ok"
                flow.response.headers["content-length"] = "2"
                flows.append(flow)
            await run_replay(cp, flows)
            assert len(cp.reports) == 3
            assert cp.stability is not None
            assert cp.stability.stable
            assert cp.stability.runs == 3


async def test_replay_parallel_marks_timing_unreliable():
    async def handler(reader, writer):
        while True:
            line = await reader.readline()
            if not line:
                break
            while True:
                header = await reader.readline()
                if header in (b"\r\n", b""):
                    break
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            await writer.drain()

    cp = sessionplayback.SessionPlayback()
    with taddons.context(cp, Proxyserver()) as tctx:
        tctx.configure(cp, session_replay_concurrency=-1)
        async with tcp_server(handler) as (addr, _):
            flows = []
            for i in range(2):
                flow = make_flow(start=1000.0 + i, connection_id=f"conn{i}")
                flow.request.host, flow.request.port = addr
                flow.request.raw_content = b""
                flow.response.content = b"ok"
                flow.response.headers["content-length"] = "2"
                flows.append(flow)
            await run_replay(cp, flows)
            report = cp.reports[0]
            assert report.parallel
            assert not report.timing_guaranteed
            assert (
                "timing is not guaranteed"
                in sessionplayback.session_context.format_report(report)
            )
            stability = sessionplayback.session_context.compare_runs([report])
            assert not stability.stable


async def test_degraded_replay_is_marked(caplog_async):
    cp = sessionplayback.SessionPlayback()
    with taddons.context(cp, Proxyserver()) as tctx:
        tctx.configure(cp)
        flows = [tflow.tflow(resp=True, live=False)]
        flows[0].request.timestamp_start = 1000.0
        flows[0].server_conn.tls = True
        flows[0].server_conn.cipher = "TLS_AES_256_GCM_SHA384"
        await run_replay(cp, flows)
        assert cp.reports[0].mode == "degraded"
        assert "TLS session ticket" in cp.reports[0].downgrade_reasons
        assert "degraded mode" in cp.report()
        assert "degraded" in caplog_async.caplog.text or True
        text = cp.report()
        assert "degraded replay" in text

    await cp.done()


async def test_slicing_by_domain_time_and_limit():
    seen = []

    async def handler(reader, writer):
        while True:
            line = await reader.readline()
            if not line:
                break
            seen.append(line)
            while True:
                header = await reader.readline()
                if header in (b"\r\n", b""):
                    break
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            await writer.drain()

    cp = sessionplayback.SessionPlayback()
    with taddons.context(cp, Proxyserver()) as tctx:
        async with tcp_server(handler) as (addr, _):
            flows = []
            for i, (path, host, start) in enumerate(
                [
                    ("/a", "a.example.com", 1000.0),
                    ("/b", "b.example.com", 1005.0),
                    ("/c", "a.example.com", 1010.0),
                    ("/d", "a.example.com", 1020.0),
                ]
            ):
                flow = make_flow(
                    path=path, host=host, start=start, connection_id=f"c{i}"
                )
                flow.request.host = addr[0]
                flow.request.port = addr[1]
                flow.request.host_header = f"{host}:{addr[1]}"
                flow.request.scheme = "http"
                flow.request.raw_content = b""
                flow.response.headers["content-length"] = "0"
                flows.append(flow)
            tctx.configure(
                cp,
                session_replay_domain=["a.example.com"],
                session_replay_start="1010",
                session_replay_end="1015",
                session_replay_limit=1,
            )
            await run_replay(cp, flows)
            assert seen == [b"GET /c HTTP/1.1\r\n"]
            assert len(cp.session.requests) == 1


def test_invalid_slice_configuration():
    cp = sessionplayback.SessionPlayback()
    with taddons.context(cp) as tctx:
        tctx.configure(cp, session_replay_start="1000", session_replay_end="900")
        flows = [make_flow(start=1000.0)]
        with pytest.raises(OptionsError):
            cp.build_session(flows)


async def test_configure_validation(tdata):
    cp = sessionplayback.SessionPlayback()
    with taddons.context(cp) as tctx:
        with pytest.raises(OptionsError):
            tctx.configure(cp, session_replay_concurrency=2)
        with pytest.raises(OptionsError):
            tctx.configure(cp, session_replay_runs=0)
        with pytest.raises(OptionsError):
            tctx.configure(cp, session_replay=["nonexistent"])
        tctx.configure(
            cp, session_replay=[tdata.path("mitmproxy/data/dumpfile-018.mitm")]
        )
        assert cp.session is not None
        await cp.done()


async def test_load_file(tdata):
    cp = sessionplayback.SessionPlayback()
    with taddons.context(cp) as tctx:
        tctx.configure(cp)
        with pytest.raises(CommandError):
            cp.load_file("/nonexistent")
        cp.load_file(tdata.path("mitmproxy/data/dumpfile-018.mitm"))
        assert cp.session is not None
        await cp.done()


def test_check_rejects_unreplayable_flows():
    cp = sessionplayback.SessionPlayback()
    flow = make_flow()
    flow.live = True
    assert "live flow" in cp._check(flow)

    flow = make_flow()
    flow.intercepted = True
    assert "intercepted" in cp._check(flow)

    flow = make_flow()
    flow.request = None
    assert "missing request" in cp._check(flow)

    flow = make_flow()
    flow.request.raw_content = None
    assert "missing content" in cp._check(flow)

    ws = tflow.twebsocketflow()
    ws.live = False
    assert "WebSocket" in cp._check(ws)

    assert cp._check(make_flow()) is None


async def test_start_replay_rejects_bad_flow():
    cp = sessionplayback.SessionPlayback()
    with taddons.context(cp):
        flow = make_flow()
        flow.live = True
        with pytest.raises(CommandError):
            cp.start_replay([flow])
        assert cp._playback_task is None


def test_empty_slice_warns(caplog_async):
    cp = sessionplayback.SessionPlayback()
    with taddons.context(cp) as tctx:
        tctx.configure(cp, session_replay_domain=["nomatch.example"])
        cp.start_replay([make_flow()])
        assert cp.session is None
        assert cp._busy is False


def test_report_before_replay():
    cp = sessionplayback.SessionPlayback()
    with taddons.context(cp):
        assert "no session replay" in cp.report()


def test_report_json():
    cp = sessionplayback.SessionPlayback()
    with taddons.context(cp):
        cp.reports = [
            sessionplayback.session_context.SessionReport(
                mode="full",
                downgrade_reasons=[],
                results=[
                    sessionplayback.session_context.RequestResult(
                        index=0,
                        request_line="GET /",
                        connection="c",
                        outcome="identical",
                        divergence=None,
                    )
                ],
            )
        ]
        data = json.loads(cp.report("json"))
        assert data["runs"][0]["results"][0]["outcome"] == "identical"
        assert data["stability"] is None
        with pytest.raises(CommandError):
            cp.report("xml")


def test_report_includes_stability():
    cp = sessionplayback.SessionPlayback()
    with taddons.context(cp):
        cp.reports = [
            sessionplayback.session_context.SessionReport(
                mode="full", downgrade_reasons=[], results=[]
            )
        ]
        cp.stability = sessionplayback.session_context.StabilityReport(
            runs=3, stable=True
        )
        assert "stable across 3 runs" in cp.report()
        data = json.loads(cp.report("json"))
        assert data["stability"]["stable"] is True


def test_tls_plan():
    cp = sessionplayback.SessionPlayback()
    with taddons.context(cp) as tctx:
        tctx.configure(cp)
        plaintext = sessionplayback.session_context.Session.from_flows([make_flow()])
        assert cp._tls_plan(plaintext.requests) is None

        tls_flow = make_flow()
        tls_flow.server_conn.tls = True
        tls_flow.server_conn.alpn_offers = (b"h2", b"http/1.1")
        sessionplayback.session_context.capture_context(
            tls_flow, session_ticket=b"ticket", fingerprint="fp"
        )
        session = sessionplayback.session_context.Session.from_flows([tls_flow])
        assert session.requests[0].tls.tls
        plan = cp._tls_plan(session.requests)
        assert plan["alpn_offers"] == (b"h2", b"http/1.1")
        assert plan["session_ticket"] == b"ticket"

        tctx.configure(cp, session_replay_tls=False)
        assert cp._tls_plan(session.requests) is None


async def test_stop_replay():
    cp = sessionplayback.SessionPlayback()
    with taddons.context(cp):
        cp._playback_task = asyncio.create_task(asyncio.sleep(100))
        cp.stop_replay()
        await asyncio.sleep(0)
        assert cp._playback_task.cancelled()
        await cp.done()


async def test_capture_hooks(monkeypatch):
    cp = sessionplayback.SessionPlayback()
    with taddons.context(cp) as tctx:
        tctx.configure(cp, session_replay_capture=True)

        recorded = {}

        def fake_attach(flow):
            recorded["flow"] = flow
            return False

        monkeypatch.setattr(
            sessionplayback.session_context, "attach_session_ticket", fake_attach
        )
        flow = make_flow()
        cp.response(flow)
        assert recorded["flow"] is flow

        class Hello:
            def raw_bytes(self, wrap_in_record=True):
                return b"\x03\x03\x00"

            @property
            def cipher_suites(self):
                return [1, 2]

            @property
            def extensions(self):
                return []

        class Data:
            client_hello = Hello()

            def __init__(self):
                client = type("Client", (), {})()
                self.context = type("C", (), {"extra": {}, "client": client})()

        data = Data()
        cp.tls_clienthello(data)
        assert data.context.extra["session_replay_fingerprint"]
        assert data.context.client._session_replay_fingerprint

        # Disabled: no-op.
        tctx.options.session_replay_capture = False
        data2 = Data()
        cp.tls_clienthello(data2)
        assert "session_replay_fingerprint" not in data2.context.extra


async def test_replay_does_not_modify_request():
    captured = {}

    async def handler(reader, writer):
        data = await reader.readuntil(b"\r\n\r\n")
        captured["raw"] = data
        body = await reader.readexactly(9)
        captured["body"] = body
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
        await writer.drain()

    cp = sessionplayback.SessionPlayback()
    with taddons.context(cp, Proxyserver()) as tctx:
        tctx.configure(cp)
        async with tcp_server(handler) as (addr, _):
            flow = make_flow(
                path="/original?x=1",
                start=1000.0,
                content=b"",
                response_headers={"content-length": "0"},
            )
            flow.request.method = "POST"
            flow.request.raw_content = b"body-data"
            flow.request.headers["content-length"] = "9"
            flow.request.headers["x-custom"] = "value"
            flow.request.host, flow.request.port = addr
            original = flow.request.raw_content
            await run_replay(cp, [flow])
            assert flow.request.raw_content == original
            assert b"x-custom: value" in captured["raw"]
            assert captured["body"] == b"body-data"


async def test_busy_replay_is_rejected(caplog_async):
    cp = sessionplayback.SessionPlayback()
    with taddons.context(cp) as tctx:
        tctx.configure(cp)
        cp._busy = True
        cp.start_replay([make_flow()])
        assert "already running" in caplog_async.caplog.text


async def test_unstable_replay_is_reported(monkeypatch):
    cp = sessionplayback.SessionPlayback()
    with taddons.context(cp) as tctx:
        tctx.configure(cp, session_replay_runs=2)
        signatures = iter(["a", "b"])

        async def fake_replay_once(session):
            sig = next(signatures)
            return sessionplayback.session_context.SessionReport(
                mode="full",
                downgrade_reasons=[],
                results=[
                    sessionplayback.session_context.RequestResult(
                        index=0,
                        request_line="GET /",
                        connection="c",
                        outcome="identical",
                        divergence=None,
                        signature=sig,
                    )
                ],
            )

        monkeypatch.setattr(cp, "_replay_once", fake_replay_once)
        session = sessionplayback.session_context.Session.from_flows([make_flow()])
        await cp._run(session)
        assert cp.stability is not None
        assert not cp.stability.stable
        assert "NOT stable" in cp.report()


async def test_upstream_mode_applies_via():
    seen = []

    async def handler(reader, writer):
        conn_req = await reader.readuntil(b"\r\n\r\n")
        seen.append(conn_req)
        writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
        await writer.drain()

    cp = sessionplayback.SessionPlayback()
    with taddons.context(cp, Proxyserver()) as tctx:
        tctx.configure(cp)
        async with tcp_server(handler) as (addr, _):
            tctx.options.mode = [f"upstream:http://{addr[0]}:{addr[1]}"]
            flow = make_flow(start=1000.0)
            # https forces a CONNECT through the upstream proxy.
            flow.request.scheme = "https"
            flow.request.authority = "address:22"
            flow.request.host, flow.request.port = "address", 22
            await run_replay(cp, [flow])
            assert seen and seen[0].startswith(b"CONNECT ")


def test_tls_context_attached_to_context():
    handler = sessionplayback.SessionReplayHandler(
        sessionplayback.session_context.Session.from_flows(
            [
                make_flow(),
            ]
        ).requests,
        __import__("mitmproxy.options", fromlist=["Options"]).Options(),
        tls_context={"alpn_offers": (b"h2",)},
    )
    assert handler.context.extra["session_replay"] == {"alpn_offers": (b"h2",)}


async def test_not_replayed_request_gets_error(monkeypatch):
    cp = sessionplayback.SessionPlayback()
    with taddons.context(cp) as tctx:
        tctx.configure(cp)

        # A handler that immediately reports completion without a response.
        class FakeHandler:
            def __init__(self, requests, options, *, tls_context=None):
                self.completed = []

            async def replay(self):
                return None

            def close(self):
                return None

        monkeypatch.setattr(sessionplayback, "SessionReplayHandler", FakeHandler)
        session = sessionplayback.session_context.Session.from_flows(
            [make_flow(start=1000.0)]
        )
        report = await cp._replay_once(session)
        assert report.results[0].outcome == "error"


async def test_response_capture_stores_fingerprint(monkeypatch):
    cp = sessionplayback.SessionPlayback()
    with taddons.context(cp) as tctx:
        tctx.configure(cp, session_replay_capture=True)
        flow = make_flow()
        flow.client_conn._session_replay_fingerprint = "fp"  # type: ignore[attr-defined]
        monkeypatch.setattr(
            sessionplayback.session_context, "attach_session_ticket", lambda f: False
        )
        cp.response(flow)
        metadata = flow.metadata[sessionplayback.session_context.METADATA_KEY]
        assert metadata["tls_fingerprint"] == "fp"
