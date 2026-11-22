---
title: "Session Replay"
weight: 5
---

# Session Replay

Client replay (`replay.client`) resends captured requests, but it does not
reproduce the conditions under which they were captured. The server sees a
brand-new client: requests that originally shared a connection arrive on
different ones, cookies are whatever the replaying client has *now* rather than
what was valid *then*, and the TLS handshake has a different fingerprint.

Session replay (`replay.session`) replays a captured session together with its
context:

- **Connection order.** Requests that were sent on the same upstream connection
  are replayed on one connection, in their original order.
- **Cookies.** Every request is replayed exactly as captured, including the
  `Cookie` header that was valid at that point in time.
- **TLS parameters.** Captured ALPN offers and TLS session tickets are applied
  to the upstream connection where possible.
- **Divergence point.** Every replayed response is compared against the
  captured one; the report names the first request at which they diverge, and
  how many requests before it matched.
- **Stability.** Replaying the same capture several times must produce the same
  result. The report states whether it did.
- **Slicing.** Large captures can be limited by domain, time window and request
  count. Slicing always happens at request boundaries.

## Basic usage

```bash
# Replay a capture, three times, and check that the results are identical.
mitmdump \
    --set session_replay=capture.mitm \
    --set session_replay_runs=3

# Inspect the report (text or json).
mitmdump -s session_report.py
```

```python
# session_report.py
from mitmproxy import ctx


def done():
    print(ctx.master.commands.execute("replay.session.report text"))
```

The report looks like this:

```
session replay: degraded mode (3 requests, serial)
degraded replay: TLS session ticket
first divergence at request 3; 3 preceding requests match
  [0] GET /login: ok
  [1] POST /api/session: ok
  [2] GET /api/me: ok
  [3] POST /api/cart: behavioral (response body differs)
```

## Slicing

A capture with tens of thousands of requests is rarely replayable end to end.
Slice it to the part you care about:

```bash
mitmdump \
    --set session_replay=capture.mitm \
    --set session_replay_domain=api.example.com \
    --set session_replay_domain='*.example.org' \
    --set session_replay_start=2026-01-01T12:00:00Z \
    --set session_replay_end=2026-01-01T12:05:00Z \
    --set session_replay_limit=200
```

Slices never split a request in half: a request is either replayed completely
or not at all. Domain patterns are shell-style globs; `example.com:8443`
matches a specific port.

## Concurrency

Requests on one connection have ordering dependencies, so replaying them in
parallel would present the server with a different sequence than the original.
By default, session replay is strictly serial.

Setting `session_replay_concurrency=-1` replays different connections in
parallel. This is faster, but relative timing is no longer guaranteed. The
report says so explicitly:

```
timing is not guaranteed: requests were replayed in parallel,
relative ordering may differ from the capture
```

The stability check always fails for parallel replay, because parallel replay is
not deterministic by design.

## Degraded replay

Some context cannot always be reproduced:

| Missing | Consequence |
| --- | --- |
| TLS session ticket | the upstream connection performs a full handshake; session resumption is not replayed |
| TLS ClientHello fingerprint | the replayed handshake has a different fingerprint than the original client |

When any of these are missing, the replay is marked as *degraded* and the report
states exactly which pieces could not be reproduced. Session replay never claims
fingerprint parity it cannot deliver.

Non-volatile response differences are reported as `behavioral`; differences that
are expected to change between runs (`Date`, `Expires`, cookie expiry and similar
headers) are reported as `environmental`. This distinction is what lets you
decide whether a difference is an actual behaviour change or just a different
environment.

## Capturing TLS context

Session replay works with any existing capture; it simply reports what it cannot
reproduce. To also capture TLS session tickets and ClientHello fingerprints for
future replays, enable capture while recording:

```bash
mitmdump --set session_replay_capture=true --save-stream-file capture.mitm
```

Session tickets and fingerprints are stored in each flow's `metadata` under the
`session_replay` key. Request and response contents are never modified.

## Commands

| Command | Description |
| --- | --- |
| `replay.session flows` | Replay the given flows as one session. |
| `replay.session.file path` | Load flows from a file and replay them as one session. |
| `replay.session.report [text\|json]` | Return the report of the last replay. |
| `replay.session.stop` | Abort the running replay. |
