"""
Session-context model for replaying captured HTTP sessions.

mitmproxy's client replay (`replay.client`) sends the captured requests, but
it does not preserve the conditions under which they were captured: the order
in which requests shared a connection, the cookies that were valid at that
exact point in time, or the TLS parameters of the upstream connection. This
module turns a list of captured flows into a `Session`, which can be sliced,
inspected and compared. The actual replay is driven by
`mitmproxy.addons.sessionplayback`.

Everything in here is deterministic and side-effect free so that replay
reports are reproducible.
"""

from __future__ import annotations

import base64
import datetime
import fnmatch
import hashlib
from dataclasses import dataclass
from dataclasses import field
from typing import Any
from typing import Literal
from typing import Sequence

from mitmproxy import http
from mitmproxy.net.http import cookies

METADATA_KEY = "session_replay"
"""Key under which capture-time session context is stored in `flow.metadata`."""

VOLATILE_HEADERS = frozenset(
    {
        "age",
        "connection",
        "content-length",
        "date",
        "expires",
        "keep-alive",
        "last-modified",
        "transfer-encoding",
    }
)
"""Headers that commonly differ between two replays for environmental reasons."""

VOLATILE_COOKIE_ATTRS = frozenset({"expires", "max-age"})
"""Cookie attributes that are expected to change when a response is refreshed."""


# ---------------------------------------------------------------------------
# TLS ClientHello fingerprints
# ---------------------------------------------------------------------------


def _read_u16_list(body: bytes) -> list[int]:
    """Parse a length-prefixed list of uint16 values (a TLS vector)."""
    if len(body) < 2:
        return []
    length = int.from_bytes(body[:2], "big")
    data = body[2 : 2 + length]
    return [int.from_bytes(data[i : i + 2], "big") for i in range(0, len(data) - 1, 2)]


def _read_u8_list(body: bytes) -> list[int]:
    """Parse a length-prefixed list of uint8 values (a TLS vector)."""
    if len(body) < 1:
        return []
    length = body[0]
    return list(body[1 : 1 + length])


def ja3(client_hello: Any) -> str:
    """
    Compute the JA3 fingerprint of a parsed `mitmproxy.tls.ClientHello`.

    The fingerprint describes the TLS ClientHello of the *original client*.
    It cannot be reproduced byte-for-byte during replay, but it is recorded so
    that replay reports can state explicitly whether a fingerprint was available
    and how the replayed TLS parameters relate to it.
    """
    raw = client_hello.raw_bytes(wrap_in_record=False)
    version = int.from_bytes(raw[:2], "big") if len(raw) >= 2 else 0
    extensions = client_hello.extensions
    curves: list[int] = []
    point_formats: list[int] = []
    for ext_type, body in extensions:
        if ext_type == 10:
            curves = _read_u16_list(body)
        elif ext_type == 11:
            point_formats = _read_u8_list(body)
    parts = [
        str(version),
        "-".join(str(x) for x in client_hello.cipher_suites),
        "-".join(str(ext_type) for ext_type, _ in extensions),
        "-".join(str(x) for x in curves),
        "-".join(str(x) for x in point_formats),
    ]
    return hashlib.md5(",".join(parts).encode()).hexdigest()


# ---------------------------------------------------------------------------
# Capture-time context
# ---------------------------------------------------------------------------


@dataclass
class TlsContext:
    """TLS parameters that were observed for an upstream connection."""

    tls: bool = False
    sni: str | None = None
    version: str | None = None
    cipher: str | None = None
    alpn: bytes | None = None
    alpn_offers: tuple[bytes, ...] = ()
    cipher_list: tuple[str, ...] = ()
    fingerprint: str | None = None
    """JA3 fingerprint of the original upstream TLS ClientHello, if captured."""
    session_ticket: bytes | None = None
    """Serialized TLS session (including ticket) that can be replayed, if captured."""

    def missing(self) -> list[str]:
        """
        Human-readable list of TLS context pieces that cannot be replayed.

        A missing session ticket and a missing fingerprint are reported
        separately: the first degrades session resumption, the second degrades
        TLS fingerprint reproduction. We never claim fingerprint parity unless
        we actually captured one, and even then we report it as *not
        reproducible* because the replay stack negotiates TLS itself.
        """
        if not self.tls:
            return []
        missing = []
        if self.session_ticket is None:
            missing.append("TLS session ticket")
        if self.fingerprint is None:
            missing.append("TLS ClientHello fingerprint")
        else:
            missing.append(
                "TLS ClientHello fingerprint (recorded but not reproducible)"
            )
        return missing

    def summary(self) -> str:
        """Short human-readable description used in reports."""
        if not self.tls:
            return "plaintext"
        parts = ["TLS"]
        if self.version:
            parts.append(self.version)
        if self.alpn:
            parts.append(f"alpn={self.alpn.decode(errors='replace')}")
        parts.append("ticket" if self.session_ticket else "no ticket")
        return " ".join(parts)


@dataclass
class SessionRequest:
    """A single captured request plus the context it was sent in."""

    flow: http.HTTPFlow
    index: int
    connection: str
    """Grouping key for requests that shared one upstream connection."""
    started: float
    ended: float | None
    cookie_header: str | None
    tls: TlsContext
    original_response: http.Response | None
    original_error: str | None

    @property
    def request_line(self) -> str:
        return f"{self.flow.request.method} {self.flow.request.path}"

    def __repr__(self) -> str:
        return f"SessionRequest(index={self.index}, {self.request_line})"


def parse_time(value: str | float | int) -> float:
    """
    Parse a timestamp for slicing.

    Accepts unix timestamps and ISO 8601 strings. Naive ISO timestamps are
    interpreted as UTC so that slicing is independent of the local timezone.
    """
    if isinstance(value, (int, float)):
        return float(value)
    text = value.strip()
    if not text:
        raise ValueError("empty timestamp")
    try:
        return float(text)
    except ValueError:
        pass
    iso = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        parsed = datetime.datetime.fromisoformat(iso)
    except ValueError as e:
        raise ValueError(f"Invalid timestamp: {value}") from e
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.timezone.utc)
    return parsed.timestamp()


def _metadata(flow: http.HTTPFlow) -> dict[str, Any]:
    data = flow.metadata.get(METADATA_KEY)
    return data if isinstance(data, dict) else {}


def _decode_ticket(value: Any) -> bytes | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return base64.b64decode(value.encode(), validate=True)
    except ValueError:
        return None


def tls_context(flow: http.HTTPFlow) -> TlsContext:
    """
    Extract upstream TLS context from a captured flow and its metadata.

    This deliberately describes the *server* connection. The client connection
    is not replayed: the replayed requests originate from mitmproxy itself, so
    only the parameters the upstream server saw can be preserved.
    """
    metadata = _metadata(flow)
    server = flow.server_conn
    return TlsContext(
        tls=bool(
            server
            and (server.tls or server.cipher is not None or server.alpn is not None)
        ),
        sni=server.sni if server else None,
        version=server.tls_version if server else None,
        cipher=server.cipher if server else None,
        alpn=server.alpn if server else None,
        alpn_offers=tuple(server.alpn_offers or ()) if server else (),
        cipher_list=tuple(server.cipher_list or ()) if server else (),
        fingerprint=metadata.get("tls_fingerprint") or None,
        session_ticket=_decode_ticket(metadata.get("tls_session_ticket")),
    )


def capture_context(
    flow: http.HTTPFlow,
    *,
    fingerprint: str | None = None,
    session_ticket: bytes | None = None,
) -> None:
    """
    Store capture-time context in `flow.metadata` (mutating the flow).

    Only TLS details that cannot be reconstructed from the flow itself are
    stored. Cookies and timestamps are already part of the captured flow.
    """
    metadata = dict(_metadata(flow))
    if fingerprint:
        metadata["tls_fingerprint"] = fingerprint
    if session_ticket:
        metadata["tls_session_ticket"] = base64.b64encode(session_ticket).decode()
    if metadata:
        flow.metadata[METADATA_KEY] = metadata


_live_sessions: dict[str, Any] = {}
"""Maps a captured server connection id to its live pyOpenSSL connection."""


def register_live_session(conn_id: str, ssl_conn: Any) -> None:
    """
    Remember the TLS connection of an upstream server for capture.

    Session tickets (in particular for TLS 1.3) only become available after the
    handshake, potentially after the first application data was read. Keeping a
    reference lets us snapshot the session when the corresponding flow is done.
    """
    _live_sessions[conn_id] = ssl_conn


def forget_live_session(conn_id: str) -> None:
    _live_sessions.pop(conn_id, None)


def snapshot_tls_session(conn_id: str) -> bytes | None:
    """
    Serialize the TLS session of a live upstream connection.

    Returns `None` if no session is available. For TLS 1.3 the ticket may not
    have arrived yet if no application data has been read; that is a normal
    situation and reported as a degraded capture.
    """
    from mitmproxy.net import tls as net_tls

    ssl_conn = _live_sessions.get(conn_id)
    if ssl_conn is None:
        return None
    session = ssl_conn.get_session()
    if session is None:  # pragma: no cover - despite established TLS
        return None
    try:
        return net_tls.serialize_session(session)
    except ValueError:  # pragma: no cover - memory error
        return None


def attach_session_ticket(flow: http.HTTPFlow) -> bool:
    """
    Snapshot the TLS session for a completed flow and store it in metadata.

    Returns `True` if a session ticket was stored. TLS flows without an
    available ticket are marked as degraded; the replay then reports that the
    session could not be reproduced instead of silently pretending otherwise.
    """
    server = flow.server_conn
    if server is None:
        return False
    ticket = snapshot_tls_session(server.id)
    if ticket is None:
        return False
    capture_context(flow, session_ticket=ticket)
    return True


def client_fingerprint(client_hello: Any) -> str:
    """Compute the JA3 fingerprint of a captured ClientHello."""
    return ja3(client_hello)


def _server_visible_headers(response: http.Response) -> list[tuple[str, str, Any]]:
    """
    Normalize response headers for comparison, splitting cookies separately.

    Returns a list of `(name, value, cookie_identity)` tuples. Cookie identity
    keeps the cookie name/value/attributes but drops volatile expiry data.
    """
    ret: list[tuple[str, str, Any]] = []
    for name, value in response.headers.items(multi=True):
        lname = name.lower()
        if lname in VOLATILE_HEADERS:
            continue
        if lname == "set-cookie":
            try:
                parsed = cookies.parse_set_cookie_header(value)
            except ValueError:  # pragma: no cover - parser is lenient
                ret.append((lname, value, None))
            else:
                for cookie_name, cookie_value, attrs in parsed:
                    stable = tuple(
                        sorted(
                            (k.lower(), v)
                            for k, v in attrs.items(multi=True)
                            if k.lower() not in VOLATILE_COOKIE_ATTRS
                        )
                    )
                    ret.append(("set-cookie", f"{cookie_name}={cookie_value}", stable))
        else:
            ret.append((lname, value, None))
    return sorted(ret, key=repr)


def response_signature(response: http.Response | None) -> str | None:
    """
    A stable digest of the parts of a response that should not vary between
    identical replays. Volatile headers and cookie expiries are ignored.
    """
    if response is None:
        return None
    digest = hashlib.sha256()
    digest.update(str(response.status_code).encode())
    digest.update(b"\0")
    for name, value, cookie_identity in _server_visible_headers(response):
        digest.update(name.encode())
        digest.update(b"=")
        digest.update(value.encode(errors="surrogateescape"))
        digest.update(b"=")
        digest.update(repr(cookie_identity).encode())
        digest.update(b"\0")
    body = response.raw_content or b""
    digest.update(hashlib.sha256(body).digest())
    return digest.hexdigest()


def compare_responses(
    original: http.Response | None,
    replayed: http.Response | None,
    *,
    original_error: str | None = None,
    replayed_error: str | None = None,
) -> tuple[str, str | None, list[tuple[str, str, str]]]:
    """
    Compare an original and a replayed response.

    Returns `(outcome, divergence, details)` where outcome is one of
    `identical`, `environmental`, `behavioral`, `error`, `unverifiable`.

    `environmental` means the responses differ only in fields that naturally
    change between two runs (timestamps, expiry dates, hop-by-hop headers).
    `behavioral` means a meaningful difference was observed.
    """
    details: list[tuple[str, str, str]] = []

    if original is None:
        if original_error:
            return ("unverifiable", f"original error: {original_error}", [])
        return ("unverifiable", "original response was not captured", [])
    if replayed is None:
        message = replayed_error or "no response received during replay"
        return ("error", message, [])

    if original.status_code != replayed.status_code:
        return (
            "behavioral",
            f"status {original.status_code} != {replayed.status_code}",
            [("status", str(original.status_code), str(replayed.status_code))],
        )

    original_headers = _server_visible_headers(original)
    replayed_headers = _server_visible_headers(replayed)

    if original_headers != replayed_headers:
        for item in original_headers:
            if item not in replayed_headers:
                details.append(("header", repr(item), "<missing>"))
        for item in replayed_headers:
            if item not in original_headers:
                details.append(("header", "<missing>", repr(item)))
        if not details:  # pragma: no cover - ordering-only differences
            details.append(("header", repr(original_headers), repr(replayed_headers)))
        return ("behavioral", "response headers differ", details)

    original_body = original.raw_content or b""
    replayed_body = replayed.raw_content or b""
    if original_body != replayed_body:
        details.append(
            ("body", f"{len(original_body)} bytes", f"{len(replayed_body)} bytes")
        )
        return ("behavioral", "response body differs", details)

    # Body and meaningful headers match. Check whether volatile fields differ.
    environmental: list[tuple[str, str, str]] = []
    for name in sorted(VOLATILE_HEADERS):
        original_value = original.headers.get(name)
        replayed_value = replayed.headers.get(name)
        if original_value != replayed_value:
            environmental.append(
                (f"header:{name}", str(original_value), str(replayed_value))
            )
    original_cookies = list(original.headers.get_all("set-cookie"))
    replayed_cookies = list(replayed.headers.get_all("set-cookie"))
    for original_cookie, replayed_cookie in zip(original_cookies, replayed_cookies):
        if original_cookie != replayed_cookie:
            environmental.append(
                ("header:set-cookie", original_cookie, replayed_cookie)
            )
    if environmental:
        return ("environmental", "environmental differences", environmental)
    return ("identical", None, [])


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------


@dataclass
class Session:
    """An ordered set of captured requests with their session context."""

    requests: list[SessionRequest] = field(default_factory=list)

    @classmethod
    def from_flows(cls, flows: Sequence[http.HTTPFlow]) -> Session:
        """
        Build a session from captured flows.

        Requests are ordered by their capture timestamps; the original input
        order breaks ties. This ordering is used for all subsequent replay
        decisions, which makes replay deterministic.
        """
        requests: list[SessionRequest] = []
        for position, flow in enumerate(flows):
            if not isinstance(flow, http.HTTPFlow) or flow.request is None:
                continue
            started = flow.request.timestamp_start or 0.0
            ended = flow.response.timestamp_end if flow.response else None
            requests.append(
                SessionRequest(
                    flow=flow,
                    index=position,
                    connection="",
                    started=started,
                    ended=ended,
                    cookie_header=flow.request.headers.get("cookie"),
                    tls=tls_context(flow),
                    original_response=(
                        flow.response.copy() if flow.response is not None else None
                    ),
                    original_error=str(flow.error) if flow.error else None,
                )
            )
        requests.sort(key=lambda r: (r.started, r.index))
        for index, request in enumerate(requests):
            request.index = index
            request.connection = _connection_key(request.flow)
        return cls(requests)

    def __len__(self) -> int:
        return len(self.requests)

    def __iter__(self):
        return iter(self.requests)

    def slice(
        self,
        *,
        domains: Sequence[str] = (),
        start: str | float | int | None = None,
        end: str | float | int | None = None,
        limit: int = 0,
    ) -> Session:
        """
        Return a new session containing a subset of requests.

        Slicing always happens at request boundaries; a request is either fully
        included or fully excluded. `limit` is applied after all other filters.
        """
        start_ts = parse_time(start) if start is not None else None
        end_ts = parse_time(end) if end is not None else None
        if start_ts is not None and end_ts is not None and start_ts > end_ts:
            raise ValueError("slice start must not be after slice end")
        selected: list[SessionRequest] = []
        for request in self.requests:
            if domains and not any(
                host_matches(request.flow.request, pattern) for pattern in domains
            ):
                continue
            if start_ts is not None and request.started < start_ts:
                continue
            if end_ts is not None and request.started > end_ts:
                continue
            selected.append(request)
        if limit > 0:
            selected = selected[:limit]
        sliced = Session(list(selected))
        for index, request in enumerate(sliced.requests):
            request.index = index
        return sliced

    def connections(self) -> list[list[SessionRequest]]:
        """
        Group requests by the upstream connection they were sent on.

        Groups appear in the order of their first request. Requests inside a
        group keep their capture order, so replaying a group in order mirrors
        what the server saw on that connection.
        """
        groups: dict[str, list[SessionRequest]] = {}
        for request in self.requests:
            groups.setdefault(request.connection, []).append(request)
        return list(groups.values())

    def capabilities(self) -> list[str]:
        """
        Return a list of context pieces that cannot be reproduced.

        Only *upstream TLS* matters here: that is the connection context the
        replayed requests are sent on. The client-side TLS handshake between
        the original client and mitmproxy is not part of the session context.
        """
        missing: list[str] = []
        for request in self.requests:
            missing.extend(request.tls.missing())
            if request.original_response is None and request.original_error is None:
                missing.append("original response")
            if request.started <= 0:
                missing.append("request timestamp")
        seen: set[str] = set()
        unique: list[str] = []
        for item in missing:
            if item not in seen:
                seen.add(item)
                unique.append(item)
        return unique

    @property
    def mode(self) -> Literal["full", "degraded"]:
        return "degraded" if self.capabilities() else "full"


def _connection_key(flow: http.HTTPFlow) -> str:
    """
    Build a stable key identifying the upstream connection a flow was sent on.

    Captured flows store a stable connection id, which we use to group
    requests. Flows that were never sent on a connection get a unique key.
    """
    server = flow.server_conn
    address = ""
    if server and server.address:
        address = f"{server.address[0]}:{server.address[1]}@"
    if server and server.id and server.timestamp_start is not None:
        return f"server:{address}{server.id}"
    return f"flow:{flow.id}"


def _split_host_port(pattern: str) -> tuple[str, int | None]:
    """Split a slice pattern into host part and optional port."""
    host, sep, port_text = pattern.rpartition(":")
    if sep and host and (port_text.isdigit() or port_text == "*"):
        return host, int(port_text) if port_text.isdigit() else None
    return pattern, None


def host_matches(request: http.Request, pattern: str) -> bool:
    """Match a request against a domain slice pattern."""
    pattern = pattern.strip().lower()
    if not pattern:
        return False
    host, port = _split_host_port(pattern)
    if port is not None and request.port != port:
        return False
    host = host.rstrip(".")
    if host.startswith("*."):
        return fnmatch.fnmatchcase(request.pretty_host.lower(), host) or (
            request.pretty_host.lower().rstrip(".") == host[2:]
        )
    return fnmatch.fnmatchcase(request.pretty_host.lower().rstrip("."), host)


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------


@dataclass
class RequestResult:
    """The outcome of replaying and comparing a single request."""

    index: int
    request_line: str
    connection: str
    outcome: str
    divergence: str | None
    details: list[tuple[str, str, str]] = field(default_factory=list)
    replayed_response: str | None = None
    signature: str | None = None

    @property
    def matched(self) -> bool:
        return self.outcome in ("identical", "environmental")


@dataclass
class SessionReport:
    """The result of replaying one session."""

    mode: Literal["full", "degraded"]
    downgrade_reasons: list[str]
    results: list[RequestResult] = field(default_factory=list)
    parallel: bool = False
    timing_guaranteed: bool = True
    connection_order: list[list[int]] = field(default_factory=list)

    @property
    def first_divergence(self) -> int | None:
        for result in self.results:
            if not result.matched:
                return result.index
        return None

    @property
    def matching_prefix(self) -> int:
        count = 0
        for result in self.results:
            if result.matched:
                count += 1
            else:
                break
        return count

    @property
    def stable_signature(self) -> tuple[tuple[int, str | None], ...]:
        return tuple((r.index, r.signature) for r in self.results)


@dataclass
class StabilityReport:
    """Whether repeated replays of the same session produced identical results."""

    runs: int
    stable: bool
    unstable_indices: list[int] = field(default_factory=list)
    details: list[str] = field(default_factory=list)


def compare_runs(runs: Sequence[SessionReport]) -> StabilityReport:
    """
    Compare multiple replays of the same session for determinism.

    Two replays are considered identical if every request produced the same
    non-volatile response signature. Non-determinism usually indicates leftover
    state (cookies, TLS sessions, connection reuse) in the replay engine.
    """
    if not runs:
        return StabilityReport(runs=0, stable=True)
    reference = runs[0]
    if any(report.parallel for report in runs):
        return StabilityReport(
            runs=len(runs),
            stable=False,
            details=["replay order is not guaranteed with parallel replay"],
        )
    length = len(reference.results)
    if any(len(report.results) != length for report in runs):
        return StabilityReport(
            runs=len(runs),
            stable=False,
            details=["replays produced a different number of results"],
        )
    unstable: list[int] = []
    details: list[str] = []
    for position in range(length):
        signatures = [report.results[position].signature for report in runs]
        if len(set(signatures)) > 1:
            index = reference.results[position].index
            unstable.append(index)
            details.append(
                f"request {index} ({reference.results[position].request_line}) "
                f"produced {len(set(signatures))} distinct responses"
            )
    return StabilityReport(
        runs=len(runs), stable=not unstable, unstable_indices=unstable, details=details
    )


def format_report(report: SessionReport, limit: int = 20) -> str:
    """Render a session report as human-readable text."""
    lines = [
        f"session replay: {report.mode} mode "
        f"({len(report.results)} requests, "
        f"{'parallel' if report.parallel else 'serial'})"
    ]
    if report.mode == "degraded":
        lines.append("degraded replay: " + ", ".join(report.downgrade_reasons))
    if not report.timing_guaranteed:
        lines.append(
            "timing is not guaranteed: requests were replayed in parallel, "
            "relative ordering may differ from the capture"
        )
    if len(report.connection_order) > 1:
        groups = ", ".join(
            "[" + ",".join(str(i) for i in group) + "]"
            for group in report.connection_order
        )
        lines.append(f"connections: {groups}")
    first = report.first_divergence
    if first is None:
        lines.append(f"all {len(report.results)} responses match the capture")
    else:
        lines.append(
            f"first divergence at request {first}; "
            f"{report.matching_prefix} preceding requests match"
        )
    for result in report.results[:limit]:
        marker = "ok" if result.matched else result.outcome
        line = f"  [{result.index}] {result.request_line}: {marker}"
        if result.divergence:
            line += f" ({result.divergence})"
        lines.append(line)
        for name, original, replayed in result.details:
            lines.append(f"        {name}: {original!r} -> {replayed!r}")
    if len(report.results) > limit:
        lines.append(f"  ... {len(report.results) - limit} more requests")
    return "\n".join(lines)


__all__ = [
    "METADATA_KEY",
    "RequestResult",
    "Session",
    "SessionReport",
    "SessionRequest",
    "StabilityReport",
    "TlsContext",
    "capture_context",
    "compare_responses",
    "compare_runs",
    "format_report",
    "host_matches",
    "ja3",
    "parse_time",
    "response_signature",
    "tls_context",
]
