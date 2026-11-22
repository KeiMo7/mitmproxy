import pytest

from mitmproxy import http
from mitmproxy import session
from mitmproxy import tls
from mitmproxy.test import tflow
from mitmproxy.test import tutils

CLIENT_HELLO_WITH_EXTENSIONS = bytes.fromhex(
    "03033b70638d2523e1cba15f8364868295305e9c52aceabda4b5147210abc783e6e1000022c02bc02fc02cc030"
    "cca9cca8cc14cc13c009c013c00ac014009c009d002f0035000a0100006cff0100010000000010000e00000b65"
    "78616d706c652e636f6d0017000000230000000d00120010060106030501050304010403020102030005000501"
    "00000000001200000010000e000c02683208687474702f312e3175500000000b00020100000a00080006001d00"
    "170018"
)


def tls_flow(**kwargs) -> http.HTTPFlow:
    flow = tflow.tflow(resp=True, live=False, **kwargs)
    flow.server_conn.tls = True
    flow.server_conn.timestamp_tls_setup = 1000.0
    flow.server_conn.sni = "example.com"
    flow.server_conn.alpn = b"h2"
    flow.server_conn.alpn_offers = (b"h2", b"http/1.1")
    flow.server_conn.tls_version = "TLSv1.3"
    flow.server_conn.cipher = "TLS_AES_256_GCM_SHA384"
    return flow


class TestJa3:
    def test_empty_vectors(self):
        assert session._read_u16_list(b"") == []
        assert session._read_u16_list(b"\x00") == []
        assert session._read_u8_list(b"") == []

    def test_ja3(self):
        fingerprint = session.ja3(tls.ClientHello(CLIENT_HELLO_WITH_EXTENSIONS))
        # Compute it manually to be sure that the exact string is stable.
        assert fingerprint == "20dd18bdd3209ea718989030a6f93364"

    def test_ja3_no_extensions(self):
        raw = bytes.fromhex(
            "03015658a756ab2c2bff55f636814deac086b7ca56b65058c7893ffc6074f5245f70205658a75475103a152637"
            "78e1bb6d22e8bbd5b6b0a3a59760ad354e91ba20d353001a0035002f000a000500040009000300060008006000"
            "61006200640100"
        )
        assert session.ja3(tls.ClientHello(raw))


class TestCaptureContext:
    def test_session_request_repr(self):
        flow = make_flow(path="/x")
        request = session.Session.from_flows([flow]).requests[0]
        assert "GET /x" in repr(request)

    def test_roundtrip(self):
        flow = tflow.tflow(resp=True)
        session.capture_context(flow, fingerprint="abc", session_ticket=b"\x01\x02")
        context = session.tls_context(flow)
        assert context.fingerprint == "abc"
        assert context.session_ticket == b"\x01\x02"

    def test_invalid_ticket(self):
        flow = tflow.tflow(resp=True)
        flow.metadata[session.METADATA_KEY] = {"tls_session_ticket": "!!invalid!!"}
        assert session.tls_context(flow).session_ticket is None

    def test_empty(self):
        flow = tflow.tflow(resp=True)
        session.capture_context(flow)
        assert session.METADATA_KEY not in flow.metadata

    def test_non_dict_metadata(self):
        flow = tflow.tflow(resp=True)
        flow.metadata[session.METADATA_KEY] = "nope"
        assert session.tls_context(flow).fingerprint is None


class TestTlsContext:
    def test_plaintext(self):
        context = session.TlsContext()
        assert context.missing() == []
        assert context.summary() == "plaintext"

    def test_missing_everything(self):
        context = session.TlsContext(tls=True)
        assert "TLS session ticket" in context.missing()
        assert any("fingerprint" in x for x in context.missing())

    def test_fingerprint_recorded_but_not_reproducible(self):
        context = session.TlsContext(tls=True, fingerprint="abc", session_ticket=b"x")
        assert context.missing() == [
            "TLS ClientHello fingerprint (recorded but not reproducible)"
        ]
        assert context.summary() == "TLS ticket"

    def test_summary(self):
        context = session.TlsContext(
            tls=True, version="TLSv1.3", alpn=b"h2", session_ticket=b"x"
        )
        assert context.summary() == "TLS TLSv1.3 alpn=h2 ticket"


class TestParseTime:
    def test_numbers(self):
        assert session.parse_time(5) == 5.0
        assert session.parse_time("5.5") == 5.5

    def test_iso(self):
        assert session.parse_time("1970-01-01T00:00:10Z") == 10.0
        assert session.parse_time("1970-01-01T00:00:10") == 10.0

    def test_invalid(self):
        with pytest.raises(ValueError):
            session.parse_time("not a timestamp")
        with pytest.raises(ValueError):
            session.parse_time("")


def make_flow(
    path="/",
    host="example.com",
    port=80,
    content=b"",
    response_content=b"",
    start=1000.0,
    connection_id=None,
    cookie=None,
):
    flow = tflow.tflow(
        req=tutils.treq(
            host=host,
            port=port,
            method=b"GET",
            path=path.encode(),
            content=content,
        ),
        resp=http.Response.make(200, response_content, {"content-type": "text/plain"}),
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


class TestSessionFromFlows:
    def test_orders_by_timestamp(self):
        flows = [
            make_flow(path="/b", start=1010.0),
            make_flow(path="/a", start=1000.0),
        ]
        result = session.Session.from_flows(flows)
        assert [r.flow.request.path for r in result] == ["/a", "/b"]
        assert [r.index for r in result] == [0, 1]

    def test_skips_non_http(self):
        tcp = tflow.ttcpflow()
        result = session.Session.from_flows([tcp, make_flow()])
        assert len(result) == 1

    def test_ties_preserve_input_order(self):
        flows = [make_flow(path=f"/{i}", start=1000.0) for i in range(5)]
        result = session.Session.from_flows(flows)
        assert [r.flow.request.path for r in result] == [f"/{i}" for i in range(5)]

    def test_cookies_captured_at_capture_time(self):
        flow = make_flow(cookie="session=one")
        later = make_flow(cookie="session=two")
        result = session.Session.from_flows([flow, later])
        assert result.requests[0].cookie_header == "session=one"
        assert result.requests[1].cookie_header == "session=two"

    def test_connection_grouping(self):
        flows = [
            make_flow(path="/a", start=1.0, connection_id="c1"),
            make_flow(path="/b", start=2.0, connection_id="c2"),
            make_flow(path="/c", start=3.0, connection_id="c1"),
        ]
        result = session.Session.from_flows(flows)
        groups = [
            [r.flow.request.path for r in group] for group in result.connections()
        ]
        assert groups == [["/a", "/c"], ["/b"]]

    def test_flow_without_connection_id(self):
        flow = make_flow()
        flow.server_conn.id = ""
        result = session.Session.from_flows([flow])
        assert result.requests[0].connection.startswith("flow:")

    def test_flows_without_connection_are_not_grouped(self):
        flows = [make_flow(path=f"/{i}", start=float(i)) for i in range(3)]
        result = session.Session.from_flows(flows)
        assert len(result.connections()) == 3


class TestSessionSlice:
    def make_session(self):
        return session.Session.from_flows(
            [
                make_flow(path="/a", host="a.example.com", start=1000.0),
                make_flow(path="/b", host="b.example.com", start=1010.0),
                make_flow(path="/c", host="a.example.com", start=1020.0),
            ]
        )

    def test_domains(self):
        result = self.make_session().slice(domains=["a.example.com"])
        assert [r.flow.request.path for r in result] == ["/a", "/c"]

    def test_domain_glob(self):
        result = self.make_session().slice(domains=["*.example.com"])
        assert len(result) == 3

    def test_domain_wildcard_suffix(self):
        result = self.make_session().slice(domains=["a.example.com:*"])
        assert [r.flow.request.path for r in result] == ["/a", "/c"]

    def test_domain_without_match(self):
        assert len(self.make_session().slice(domains=["nope.example"])) == 0

    def test_empty_domain_pattern(self):
        assert len(self.make_session().slice(domains=[""])) == 0

    def test_port_qualified_domain(self):
        flows = [
            make_flow(path="/a", port=80, start=1.0),
            make_flow(path="/b", port=8443, start=2.0),
        ]
        result = session.Session.from_flows(flows).slice(domains=["example.com:8443"])
        assert [r.flow.request.path for r in result] == ["/b"]

    def test_time_window(self):
        result = self.make_session().slice(start=1010.0, end=1010.0)
        assert [r.flow.request.path for r in result] == ["/b"]

    def test_limit(self):
        result = self.make_session().slice(limit=2)
        assert [r.flow.request.path for r in result] == ["/a", "/b"]

    def test_limit_zero_means_unlimited(self):
        assert len(self.make_session().slice(limit=0)) == 3

    def test_invalid_window(self):
        with pytest.raises(ValueError, match="start must not be after"):
            self.make_session().slice(start=2000, end=1000)

    def test_slicing_keeps_request_boundaries(self):
        flow = make_flow(path="/a", content=b"x" * 100, start=1000.0)
        result = session.Session.from_flows([flow]).slice(limit=1)
        assert result.requests[0].flow.request.raw_content == b"x" * 100

    def test_slice_resets_indices(self):
        result = self.make_session().slice(start=1010.0)
        assert [r.index for r in result] == [0, 1]


class TestSessionCapabilities:
    def test_plain_degraded_due_to_missing_response(self):
        flow = tflow.tflow(live=False)
        flow.response = None
        result = session.Session.from_flows([flow])
        assert result.mode == "degraded"
        assert "original response" in result.capabilities()

    def test_tls_degraded(self):
        result = session.Session.from_flows([tls_flow()])
        assert result.mode == "degraded"
        assert "TLS session ticket" in result.capabilities()

    def test_full(self):
        flow = make_flow()
        session.capture_context(flow, session_ticket=b"x")
        result = session.Session.from_flows([flow])
        assert result.mode == "full"

    def test_missing_timestamp(self):
        flow = make_flow(start=0.0)
        result = session.Session.from_flows([flow])
        assert "request timestamp" in result.capabilities()


class TestCompareResponses:
    def response(self, **kwargs):
        headers = kwargs.pop("headers", {})
        return http.Response.make(
            kwargs.pop("status", 200), kwargs.pop("content", b""), headers
        )

    def test_identical(self):
        a = self.response(content=b"hi", headers={"content-type": "text"})
        b = self.response(content=b"hi", headers={"content-type": "text"})
        outcome, divergence, details = session.compare_responses(a, b)
        assert outcome == "identical"
        assert divergence is None
        assert details == []

    def test_unverifiable(self):
        outcome, _, _ = session.compare_responses(None, self.response())
        assert outcome == "unverifiable"

    def test_original_error(self):
        outcome, divergence, _ = session.compare_responses(
            None, self.response(), original_error="boom"
        )
        assert outcome == "unverifiable"
        assert "boom" in divergence

    def test_error(self):
        outcome, divergence, _ = session.compare_responses(
            self.response(), None, replayed_error="connection refused"
        )
        assert outcome == "error"
        assert divergence == "connection refused"

    def test_error_without_message(self):
        outcome, divergence, _ = session.compare_responses(self.response(), None)
        assert outcome == "error"
        assert "no response" in divergence

    def test_status_differs(self):
        outcome, divergence, details = session.compare_responses(
            self.response(status=200), self.response(status=500)
        )
        assert outcome == "behavioral"
        assert "status" in divergence
        assert details[0][0] == "status"

    def test_header_differs(self):
        outcome, divergence, details = session.compare_responses(
            self.response(headers={"x": "1"}), self.response(headers={"x": "2"})
        )
        assert outcome == "behavioral"
        assert "headers" in divergence
        assert details

    def test_header_order_does_not_matter(self):
        a = self.response(headers={"a": "1", "b": "2"})
        b = self.response(headers={"b": "2", "a": "1"})
        outcome, _, _ = session.compare_responses(a, b)
        assert outcome == "identical"

    def test_body_differs(self):
        outcome, divergence, details = session.compare_responses(
            self.response(content=b"one"), self.response(content=b"two")
        )
        assert outcome == "behavioral"
        assert "body" in divergence
        assert details[0][0] == "body"

    def test_volatile_headers_are_environmental(self):
        original = self.response(headers={"date": "Mon, 01 Jan 2000 00:00:00 GMT"})
        replayed = self.response(headers={"date": "Tue, 02 Jan 2000 00:00:00 GMT"})
        outcome, divergence, details = session.compare_responses(original, replayed)
        assert outcome == "environmental"
        assert divergence == "environmental differences"
        assert details[0][0] == "header:date"

    def test_cookie_expiry_is_environmental(self):
        original = self.response(
            headers={"set-cookie": "a=b; Path=/; Expires=Mon, 01 Jan 2000 00:00:00 GMT"}
        )
        replayed = self.response(
            headers={"set-cookie": "a=b; Path=/; Expires=Tue, 02 Jan 2000 00:00:00 GMT"}
        )
        outcome, _, _ = session.compare_responses(original, replayed)
        assert outcome == "environmental"

    def test_cookie_value_is_behavioral(self):
        original = self.response(headers={"set-cookie": "a=b; Path=/"})
        replayed = self.response(headers={"set-cookie": "a=c; Path=/"})
        outcome, _, _ = session.compare_responses(original, replayed)
        assert outcome == "behavioral"

    def test_unparseable_cookie_header(self):
        a = http.Response.make(200, b"", {"set-cookie": "ok=1"})
        # Manually insert a malformed cookie value to exercise the fallback.
        a.headers["set-cookie"] = ";;;"
        b = http.Response.make(200, b"", {})
        b.headers["set-cookie"] = ";;;"
        outcome, _, _ = session.compare_responses(a, b)
        assert outcome in ("identical", "behavioral")

    def test_invalid_cookie_is_compared_verbatim(self):
        original = self.response(headers={"set-cookie": "not a cookie"})
        replayed = self.response(headers={"set-cookie": "not a cookie"})
        outcome, _, _ = session.compare_responses(original, replayed)
        assert outcome == "identical"


class TestResponseSignature:
    def test_ignores_volatile(self):
        a = http.Response.make(200, b"hi", {"date": "Mon, 01 Jan 2000 00:00:00 GMT"})
        b = http.Response.make(200, b"hi", {"date": "Tue, 02 Jan 2000 00:00:00 GMT"})
        assert session.response_signature(a) == session.response_signature(b)

    def test_includes_headers(self):
        a = http.Response.make(200, b"hi", {"x-trace": "1"})
        b = http.Response.make(200, b"hi", {"x-trace": "2"})
        assert session.response_signature(a) != session.response_signature(b)

    def test_includes_nonvolatile_cookie_attrs(self):
        a = http.Response.make(200, b"", {"set-cookie": "a=b; Path=/x"})
        b = http.Response.make(200, b"", {"set-cookie": "a=b; Path=/y"})
        assert session.response_signature(a) != session.response_signature(b)

    def test_detects_body(self):
        a = http.Response.make(200, b"hi")
        b = http.Response.make(200, b"ho")
        assert session.response_signature(a) != session.response_signature(b)

    def test_none(self):
        assert session.response_signature(None) is None


def report_for(index, outcome, signature="x"):
    return session.RequestResult(
        index=index,
        request_line=f"GET /{index}",
        connection="c",
        outcome=outcome,
        divergence=None,
        signature=signature,
    )


class TestSessionReport:
    def test_first_divergence(self):
        report = session.SessionReport(
            mode="full",
            downgrade_reasons=[],
            results=[
                report_for(0, "identical"),
                report_for(1, "environmental"),
                report_for(2, "behavioral"),
                report_for(3, "identical"),
            ],
        )
        assert report.first_divergence == 2
        assert report.matching_prefix == 2

    def test_no_divergence(self):
        report = session.SessionReport(
            mode="full", downgrade_reasons=[], results=[report_for(0, "identical")]
        )
        assert report.first_divergence is None
        assert report.matching_prefix == 1

    def test_stable_signature(self):
        report = session.SessionReport(
            mode="full", downgrade_reasons=[], results=[report_for(0, "identical")]
        )
        assert report.stable_signature == ((0, "x"),)


class TestCompareRuns:
    def make_report(self, signatures, parallel=False):
        return session.SessionReport(
            mode="full",
            downgrade_reasons=[],
            parallel=parallel,
            results=[
                report_for(i, "identical", signature=sig)
                for i, sig in enumerate(signatures)
            ],
        )

    def test_empty(self):
        assert session.compare_runs([]).stable

    def test_stable(self):
        runs = [self.make_report(["a", "b"]) for _ in range(3)]
        result = session.compare_runs(runs)
        assert result.stable
        assert result.runs == 3

    def test_unstable(self):
        runs = [
            self.make_report(["a", "b"]),
            self.make_report(["a", "c"]),
            self.make_report(["a", "b"]),
        ]
        result = session.compare_runs(runs)
        assert not result.stable
        assert result.unstable_indices == [1]
        assert "request 1" in result.details[0]

    def test_different_lengths(self):
        runs = [self.make_report(["a"]), self.make_report(["a", "b"])]
        result = session.compare_runs(runs)
        assert not result.stable
        assert "different number of results" in result.details[0]

    def test_parallel_is_unstable(self):
        runs = [self.make_report(["a"], parallel=True)]
        result = session.compare_runs(runs)
        assert not result.stable
        assert "parallel" in result.details[0]


class TestFormatReport:
    def test_full_report(self):
        report = session.SessionReport(
            mode="degraded",
            downgrade_reasons=["TLS session ticket"],
            parallel=True,
            timing_guaranteed=False,
            results=[report_for(0, "identical"), report_for(1, "behavioral")],
        )
        text = session.format_report(report)
        assert "degraded mode" in text
        assert "degraded replay: TLS session ticket" in text
        assert "timing is not guaranteed" in text
        assert "first divergence at request 1" in text
        assert "[0] GET /0: ok" in text
        assert "[1] GET /1: behavioral" in text

    def test_divergence_detail_rendered(self):
        result = report_for(0, "behavioral")
        result.divergence = "response body differs"
        report = session.SessionReport(
            mode="full", downgrade_reasons=[], results=[result]
        )
        assert "response body differs" in session.format_report(report)

    def test_truncation(self):
        report = session.SessionReport(
            mode="full",
            downgrade_reasons=[],
            results=[report_for(i, "identical") for i in range(25)],
        )
        text = session.format_report(report, limit=2)
        assert "more requests" in text

    def test_no_divergence(self):
        report = session.SessionReport(
            mode="full", downgrade_reasons=[], results=[report_for(0, "identical")]
        )
        assert "all 1 responses match" in session.format_report(report)


class TestLiveSessions:
    def test_register_and_forget(self):
        class FakeSslConn:
            def get_session(self):
                return None

        session.register_live_session("abc", FakeSslConn())
        assert session.snapshot_tls_session("abc") is None
        session.forget_live_session("abc")
        assert session.snapshot_tls_session("abc") is None

    def test_register_and_snapshot(self, monkeypatch):
        class FakeSslConn:
            def get_session(self):
                return "session"

        monkeypatch.setattr(
            "mitmproxy.net.tls.serialize_session", lambda s: b"serialized"
        )
        session.register_live_session("abc", FakeSslConn())
        try:
            assert session.snapshot_tls_session("abc") == b"serialized"
        finally:
            session.forget_live_session("abc")

    def test_snapshot_error(self, monkeypatch):
        class FakeSslConn:
            def get_session(self):
                return "session"

        def fail(_):
            raise ValueError("nope")

        monkeypatch.setattr("mitmproxy.net.tls.serialize_session", fail)
        session.register_live_session("abc", FakeSslConn())
        try:
            assert session.snapshot_tls_session("abc") is None
        finally:
            session.forget_live_session("abc")

    def test_snapshot_without_connection(self):
        assert session.snapshot_tls_session("never-registered") is None

    def test_attach_without_tls(self):
        flow = tflow.tflow(resp=True)
        assert session.attach_session_ticket(flow) is False

    def test_attach_without_server_connection(self):
        flow = tflow.tflow(resp=True)
        flow.server_conn = None
        assert session.attach_session_ticket(flow) is False

    def test_attach_without_ticket(self, monkeypatch):
        flow = tls_flow()
        monkeypatch.setattr(session, "snapshot_tls_session", lambda conn_id: None)
        assert session.attach_session_ticket(flow) is False

    def test_attach_with_ticket(self, monkeypatch):
        flow = tls_flow()
        monkeypatch.setattr(session, "snapshot_tls_session", lambda conn_id: b"ticket")
        assert session.attach_session_ticket(flow) is True
        assert session.tls_context(flow).session_ticket == b"ticket"

    def test_client_fingerprint(self):
        assert session.client_fingerprint(
            tls.ClientHello(CLIENT_HELLO_WITH_EXTENSIONS)
        ) == session.ja3(tls.ClientHello(CLIENT_HELLO_WITH_EXTENSIONS))


def test_format_report_details_and_connections():
    result = session.RequestResult(
        index=0,
        request_line="GET /",
        connection="c",
        outcome="behavioral",
        divergence="status 200 != 500",
        details=[("status", "200", "500")],
    )
    report = session.SessionReport(
        mode="full",
        downgrade_reasons=[],
        results=[result],
        connection_order=[[0], [1, 2]],
    )
    text = session.format_report(report)
    assert "connections: [0], [1,2]" in text
    assert "status: '200' -> '500'" in text


def test_format_report_single_connection_has_no_header():
    report = session.SessionReport(
        mode="full",
        downgrade_reasons=[],
        results=[report_for(0, "identical")],
        connection_order=[[0]],
    )
    assert "connections:" not in session.format_report(report)
