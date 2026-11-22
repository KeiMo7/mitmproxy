"""
Session-context replay.

This addon replays captured HTTP sessions while preserving the context they
were captured in:

- requests that shared an upstream connection are replayed in their original
  order on that same connection,
- requests are sent exactly as captured, including the ``Cookie`` header that
  was valid at that point in time,
- captured TLS parameters (ALPN offers and session tickets) are re-applied to
  the upstream connection where possible,
- every replayed response is compared against the captured one, and the first
  request at which they diverge is reported,
- replaying the same session multiple times produces identical results, which
  is verified by an optional stability check.

Replay is opt-in via the ``session_replay`` option; the existing client replay
is left untouched.
"""

from __future__ import annotations

import asyncio
import collections
import json
import logging
from collections.abc import Callable
from collections.abc import Sequence
from typing import cast

import mitmproxy.types
from mitmproxy import command
from mitmproxy import ctx
from mitmproxy import exceptions
from mitmproxy import flow
from mitmproxy import http
from mitmproxy import io
from mitmproxy import session as session_context
from mitmproxy.addons.clientplayback import MockServer
from mitmproxy.addons.clientplayback import ReplayHandler
from mitmproxy.connection import ConnectionState
from mitmproxy.connection import Server
from mitmproxy.log import ALERT
from mitmproxy.options import Options
from mitmproxy.proxy import events
from mitmproxy.proxy import layers
from mitmproxy.proxy.context import Context
from mitmproxy.proxy.layer import CommandGenerator
from mitmproxy.proxy.layers import http as http_layer
from mitmproxy.proxy.layers.http._events import RequestData
from mitmproxy.proxy.layers.http._events import RequestEndOfMessage
from mitmproxy.proxy.layers.http._events import RequestHeaders
from mitmproxy.proxy.mode_specs import UpstreamMode
from mitmproxy.proxy.server import TimeoutWatchdog
from mitmproxy.utils import asyncio_utils

logger = logging.getLogger(__name__)

FlowCallback = Callable[[http.HTTPFlow], None]


class SessionMockServer(MockServer):
    """
    A mock HTTP client that feeds multiple captured requests, one after the
    other, into the proxy core.

    Requests are only released once the previous response is complete, which
    guarantees that the server sees them in capture order on a connection that
    is reused exactly like in the original session.
    """

    def __init__(
        self,
        requests: Sequence[session_context.SessionRequest],
        context: Context,
    ) -> None:
        # The first flow provides the connection object; the remaining ones are
        # replayed on the same mock connection.
        super().__init__(requests[0].flow, context)
        self.requests = list(requests)
        self.position = 0
        self.completed: list[http.HTTPFlow] = []
        self.on_flow_completed: FlowCallback | None = None

    @property
    def current(self) -> http.HTTPFlow:
        return self.requests[self.position].flow

    @property
    def finished(self) -> bool:
        return self.position >= len(self.requests)

    def _stream_id(self) -> int:
        # Client-side HTTP/1 streams use odd ids, incrementing by two.
        return 2 * (self.position + 1) - 1

    def _start_request(self) -> CommandGenerator[None]:
        self.flow = flow = self.current
        stream_id = self._stream_id()
        content = flow.request.raw_content
        yield layers.http.ReceiveHttp(
            RequestHeaders(
                stream_id,
                flow.request,
                end_stream=not (content or flow.request.trailers),
                replay_flow=flow,
            )
        )
        if content:
            yield layers.http.ReceiveHttp(RequestData(stream_id, content))
        if flow.request.trailers:  # pragma: no cover - HTTP/1 trailers unsupported
            yield layers.http.ReceiveHttp(
                layers.http.RequestTrailers(stream_id, flow.request.trailers)
            )
        yield layers.http.ReceiveHttp(RequestEndOfMessage(stream_id))

    def _finish_current(self) -> CommandGenerator[None]:
        flow = self.current
        if self.finished:  # pragma: no cover - late events after completion
            return
        self.completed.append(flow)
        if self.on_flow_completed:
            self.on_flow_completed(flow)
        self.position += 1
        if not self.finished:
            # Release the next request only after the previous response is
            # complete, preserving the original ordering on this connection.
            yield from self._start_request()

    def _handle_event(self, event: events.Event) -> CommandGenerator[None]:
        if isinstance(event, events.Start):
            yield from self._start_request()
        elif isinstance(event, layers.http.ResponseEndOfMessage):
            yield from self._finish_current()
        elif isinstance(event, layers.http.ResponseProtocolError):
            yield from self._finish_current()
        elif isinstance(
            event,
            (
                layers.http.ResponseHeaders,
                layers.http.ResponseData,
                layers.http.ResponseTrailers,
            ),
        ):
            pass
        else:  # pragma: no cover
            logger.warning(f"Unexpected event during session replay: {event}")


class SessionReplayHandler(ReplayHandler):
    """
    Replays one connection's worth of captured requests.
    """

    context: Context
    """The proxy context for this replay. Shadowed here for type checkers."""

    requests: list[session_context.SessionRequest]
    mock: SessionMockServer
    completed: list[http.HTTPFlow]

    def __init__(
        self,
        requests: Sequence[session_context.SessionRequest],
        options: Options,
        *,
        tls_context: dict | None = None,
    ) -> None:
        first = requests[0].flow
        client = first.client_conn.copy()
        client.state = ConnectionState.OPEN

        context = Context(client, options)
        context.server = Server(address=(first.request.host, first.request.port))
        if first.request.scheme == "https":
            context.server.tls = True
            context.server.sni = first.request.pretty_host
        upstream = bool(options.mode and options.mode[0].startswith("upstream:"))
        if upstream:
            mode = UpstreamMode.parse(options.mode[0])
            assert isinstance(mode, UpstreamMode)
            context.server.via = first.server_conn.via = (mode.scheme, mode.address)
        if tls_context:
            context.extra["session_replay"] = tls_context

        # We deliberately do not call `ReplayHandler.__init__`: it installs a
        # single-flow MockServer, while we need to drive multiple requests.
        self.context = context
        self.client = context.client
        self.transports = {}
        self.max_conns = collections.defaultdict(lambda: asyncio.Semaphore(5))
        self.wakeup_timer = set()
        self._server_event_lock = asyncio.Lock()
        self._drain_lock = asyncio.Lock()
        self.timeout_watchdog = TimeoutWatchdog(options.tcp_timeout, self.on_timeout)
        self.layer = http_layer.HttpLayer(
            context,
            http_layer.HTTPMode.upstream
            if upstream
            else http_layer.HTTPMode.transparent,
        )
        self.requests = list(requests)
        self.mock = SessionMockServer(requests, context.fork())
        self.mock.on_flow_completed = self._flow_completed
        self.layer.connections[client] = self.mock
        self.flow = first
        self.done = asyncio.Event()
        self.completed = []

    def _flow_completed(self, flow: http.HTTPFlow) -> None:
        self.completed.append(flow)
        if len(self.completed) >= len(self.requests):
            self.done.set()
            self._close_transports()

    def _close_transports(self) -> None:
        for transport in self.transports.values():
            if transport.handler is not None:
                transport.handler.cancel()

    def close(self) -> None:
        """Cancel any remaining transport tasks (used on completion and abort)."""
        self._close_transports()
        self.done.set()

    async def replay(self) -> None:
        await self.server_event(events.Start())
        await self.done.wait()

    async def handle_hook(self, hook) -> None:
        # Unlike single-flow replay we do not stop at the first response hook:
        # the mock server releases subsequent requests on its own and `done` is
        # set once every request has completed.
        (data,) = hook.args()
        await ctx.master.addons.handle_lifecycle(hook)
        if isinstance(data, flow.Flow):
            await data.wait_for_resume()


class SessionPlayback:
    """
    Replay captured sessions with their connection, cookie and TLS context.
    """

    def __init__(self) -> None:
        self.session: session_context.Session | None = None
        self.loaded_flows: list[http.HTTPFlow] = []
        self.reports: list[session_context.SessionReport] = []
        self.stability: session_context.StabilityReport | None = None
        self._playback_task: asyncio.Task | None = None
        self._busy = False

    # -- options -----------------------------------------------------------

    def load(self, loader) -> None:
        loader.add_option(
            "session_replay",
            Sequence[str],
            [],
            "Replay a captured HTTP session with its full session context "
            "(connection order, cookies, TLS parameters).",
        )
        loader.add_option(
            "session_replay_domain",
            Sequence[str],
            [],
            "Only replay requests for these domains (glob patterns, can be repeated).",
        )
        loader.add_option(
            "session_replay_start",
            str | None,
            None,
            "Only replay requests captured at or after this time "
            "(unix timestamp or ISO 8601).",
        )
        loader.add_option(
            "session_replay_end",
            str | None,
            None,
            "Only replay requests captured at or before this time "
            "(unix timestamp or ISO 8601).",
        )
        loader.add_option(
            "session_replay_limit",
            int,
            0,
            "Replay at most this many requests (0 means no limit).",
        )
        loader.add_option(
            "session_replay_concurrency",
            int,
            1,
            "Replay concurrency: 1 replays strictly serially, -1 replays "
            "different connections in parallel (relative timing is then not guaranteed).",
        )
        loader.add_option(
            "session_replay_tls",
            bool,
            True,
            "Re-apply captured TLS parameters (ALPN offers and session tickets) when replaying.",
        )
        loader.add_option(
            "session_replay_capture",
            bool,
            False,
            "Capture TLS session context (session tickets and ClientHello fingerprints) "
            "for later session replay.",
        )
        loader.add_option(
            "session_replay_runs",
            int,
            1,
            "Replay each session this many times and verify that the results are identical.",
        )

    def configure(self, updated) -> None:
        relevant = {
            "session_replay",
            "session_replay_domain",
            "session_replay_start",
            "session_replay_end",
            "session_replay_limit",
            "session_replay_concurrency",
            "session_replay_runs",
        }
        if not (relevant & set(updated)):
            return
        if ctx.options.session_replay_concurrency not in (1, -1):
            raise exceptions.OptionsError("session_replay_concurrency must be 1 or -1.")
        if ctx.options.session_replay_runs < 1:
            raise exceptions.OptionsError("session_replay_runs must be at least 1.")
        if "session_replay" in updated and ctx.options.session_replay:
            try:
                flows = io.read_flows_from_paths(ctx.options.session_replay)
            except exceptions.FlowReadException as e:
                raise exceptions.OptionsError(str(e))
            self.start_replay(flows)

    # -- capture -----------------------------------------------------------

    def tls_clienthello(self, data) -> None:
        """
        Remember the TLS fingerprint of the original client connection.

        The fingerprint describes the ClientHello the captured client sent. It
        cannot be reproduced by the replaying client, so we store it to report
        this explicitly rather than claiming fingerprint parity.
        """
        if not ctx.options.session_replay_capture:
            return
        fingerprint = session_context.ja3(data.client_hello)
        data.context.extra["session_replay_fingerprint"] = fingerprint
        # Flows created on this connection reference the same client object, so
        # attaching the fingerprint here makes it available in `response`.
        data.context.client._session_replay_fingerprint = fingerprint  # type: ignore[attr-defined]

    def response(self, flow: http.HTTPFlow) -> None:
        """
        Store capture-time context for later replay.

        This only *reads* the flow, except for the TLS metadata stored in
        `flow.metadata`. Request and response contents are never modified.
        """
        if not ctx.options.session_replay_capture:
            return
        fingerprint = None
        if flow.client_conn:
            fingerprint = getattr(flow.client_conn, "_session_replay_fingerprint", None)
        session_context.capture_context(flow, fingerprint=fingerprint)
        session_context.attach_session_ticket(flow)

    # -- slicing -----------------------------------------------------------

    def build_session(self, flows: Sequence[flow.Flow]) -> session_context.Session:
        http_flows = [
            cast(http.HTTPFlow, f) for f in flows if isinstance(f, http.HTTPFlow)
        ]
        session = session_context.Session.from_flows(http_flows)
        options = ctx.options
        try:
            return session.slice(
                domains=options.session_replay_domain,
                start=options.session_replay_start,
                end=options.session_replay_end,
                limit=options.session_replay_limit,
            )
        except ValueError as e:
            raise exceptions.OptionsError(str(e)) from e

    # -- replay ------------------------------------------------------------

    @command.command("replay.session")
    def start_replay(self, flows: Sequence[flow.Flow]) -> None:
        """
        Replay the given flows as one captured session.
        """
        session = self.build_session(flows)
        if not session.requests:
            logger.warning("No requests matched the session replay slice.")
            return
        if self._busy:
            logger.warning("A session replay is already running.")
            return
        for request in session.requests:
            err = self._check(request.flow)
            if err:
                raise exceptions.CommandError(err)
        reasons = session.capabilities()
        if reasons:
            logger.log(
                ALERT,
                "Session replay is running in degraded mode, missing context: "
                + ", ".join(reasons),
            )
        self.loaded_flows = [r.flow for r in session.requests]
        self.session = session
        self.reports = []
        self.stability = None
        self._busy = True
        self._playback_task = asyncio_utils.create_task(
            self._run(session),
            name="session playback",
            keep_ref=True,
        )

    @command.command("replay.session.file")
    def load_file(self, path: mitmproxy.types.Path) -> None:
        """
        Load flows from a file and replay them as one captured session.
        """
        try:
            flows = io.read_flows_from_paths([path])
        except exceptions.FlowReadException as e:
            raise exceptions.CommandError(str(e))
        self.start_replay(flows)

    def _check(self, flow: http.HTTPFlow) -> str | None:
        if flow.live:
            return "Can't replay live flow."
        if flow.intercepted:
            return "Can't replay intercepted flow."
        if flow.request is None:
            return "Can't replay flow with missing request."
        if flow.request.raw_content is None:
            return "Can't replay flow with missing content."
        if flow.websocket is not None:
            return "Can't replay WebSocket flows."
        return None

    async def _run(self, session: session_context.Session) -> None:
        try:
            runs = ctx.options.session_replay_runs
            for _ in range(runs):
                report = await self._replay_once(session)
                self.reports.append(report)
                logger.log(logging.INFO, session_context.format_report(report))
            if runs > 1:
                self.stability = session_context.compare_runs(self.reports)
                if self.stability.stable:
                    logger.log(
                        logging.INFO, f"session replay is stable across {runs} runs"
                    )
                else:
                    logger.log(
                        ALERT,
                        "session replay is NOT stable: "
                        + "; ".join(self.stability.details),
                    )
        except Exception:  # pragma: no cover - defensive
            logger.exception("Session replay has crashed!")
        finally:
            self._busy = False

    async def _replay_once(
        self, session: session_context.Session
    ) -> session_context.SessionReport:
        parallel = ctx.options.session_replay_concurrency == -1
        groups = session.connections()
        results: dict[int, session_context.RequestResult] = {}

        # Reset all flows to a pristine state so repeated runs are independent.
        for request in session.requests:
            request.flow.response = None
            request.flow.error = None
            request.flow.is_replay = "request"
            request.flow.backup()

        async def replay_group(
            group: Sequence[session_context.SessionRequest],
        ) -> list[http.HTTPFlow]:
            handler = SessionReplayHandler(
                group, ctx.options, tls_context=self._tls_plan(group)
            )
            try:
                await handler.replay()
            finally:
                handler.close()
            return handler.completed

        if parallel:
            done_groups = await asyncio.gather(
                *(replay_group(group) for group in groups)
            )
        else:
            done_groups = []
            for group in groups:
                done_groups.append(await replay_group(group))

        for group, completed in zip(groups, done_groups):
            for request in group:
                replayed = request.flow
                if replayed not in completed and replayed.response is None:
                    replayed.error = flow.Error("request was not replayed")
                outcome, divergence, details = session_context.compare_responses(
                    request.original_response,
                    replayed.response,
                    original_error=request.original_error,
                    replayed_error=str(replayed.error) if replayed.error else None,
                )
                results[request.index] = session_context.RequestResult(
                    index=request.index,
                    request_line=request.request_line,
                    connection=request.connection,
                    outcome=outcome,
                    divergence=divergence,
                    details=details,
                    replayed_response=(
                        str(replayed.response.status_code)
                        if replayed.response is not None
                        else None
                    ),
                    signature=session_context.response_signature(replayed.response),
                )

        return session_context.SessionReport(
            mode=session.mode,
            downgrade_reasons=session.capabilities(),
            results=[results[index] for index in sorted(results)],
            parallel=parallel,
            timing_guaranteed=not parallel,
            connection_order=[[request.index for request in group] for group in groups],
        )

    def _tls_plan(self, group: Sequence[session_context.SessionRequest]) -> dict | None:
        """
        Build the TLS context applied when replaying one connection.

        Only parameters mitmproxy can re-apply per connection are included.
        Missing session tickets are reported through the session capabilities,
        never silently ignored.
        """
        if not ctx.options.session_replay_tls:
            return None
        tls_context = group[0].tls
        if not tls_context.tls:
            return None
        plan: dict = {}
        if tls_context.alpn_offers:
            plan["alpn_offers"] = tls_context.alpn_offers
        if tls_context.session_ticket:
            plan["session_ticket"] = tls_context.session_ticket
        return plan or None

    # -- reporting ---------------------------------------------------------

    @command.command("replay.session.report")
    def report(self, format: str = "text") -> str:
        """
        Return the report of the last session replay.

        Valid formats are 'text' and 'json'.
        """
        if not self.reports:
            return "no session replay has been performed yet"
        if format == "json":
            return json.dumps(self._report_dict(), indent=2)
        if format != "text":
            raise exceptions.CommandError(f"Unknown report format: {format}")
        parts = [session_context.format_report(r) for r in self.reports]
        if self.stability is not None:
            parts.append(
                "stability: "
                + (
                    f"stable across {self.stability.runs} runs"
                    if self.stability.stable
                    else "NOT stable (" + ", ".join(self.stability.details) + ")"
                )
            )
        return "\n\n".join(parts)

    def _report_dict(self) -> dict:
        return {
            "runs": [
                {
                    "mode": run.mode,
                    "downgrade_reasons": run.downgrade_reasons,
                    "parallel": run.parallel,
                    "timing_guaranteed": run.timing_guaranteed,
                    "first_divergence": run.first_divergence,
                    "matching_prefix": run.matching_prefix,
                    "connection_order": run.connection_order,
                    "results": [
                        {
                            "index": result.index,
                            "request": result.request_line,
                            "connection": result.connection,
                            "outcome": result.outcome,
                            "divergence": result.divergence,
                            "details": result.details,
                        }
                        for result in run.results
                    ],
                }
                for run in self.reports
            ],
            "stability": None
            if self.stability is None
            else {
                "stable": self.stability.stable,
                "runs": self.stability.runs,
                "unstable_indices": self.stability.unstable_indices,
            },
        }

    @command.command("replay.session.stop")
    def stop_replay(self) -> None:
        """Abort the currently running session replay."""
        if self._playback_task is not None:
            self._playback_task.cancel()
            logger.log(ALERT, "Session replay stopped.")

    async def done(self) -> None:
        if self._playback_task is not None:
            self._playback_task.cancel()
            try:
                await self._playback_task
            except asyncio.CancelledError:
                pass
            self._playback_task = None
