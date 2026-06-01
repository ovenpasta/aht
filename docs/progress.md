# Progress

Snapshot of implementation status against [`plan.md`](plan.md).
Last updated: 2026-06-01 (Autobahn §7 close-handshake validation —
`Frames.Classify_Inbound_Close` + `test_ws_frames` cases; a received
reserved close code 1004/1005/1006/1015 now fails with 1002 and a
non-UTF-8 close reason with 1007, clearing §7 (cases 7.5.1 / 7.9.3 /
7.9.4 / 7.9.5); `Valid_Close_Code` also now excludes 1004 so it can
never be sent outbound either. On top of RFC 3629 UTF-8 validation —
`AHT.Websocket.UTF8.Is_Valid` + `test_ws_utf8`; inbound text payloads
that are ill-formed UTF-8 now fail the connection with close code 1007
per RFC 6455 §8.1, clearing all Autobahn §6 cases. On top of
`test_ws_ping`, covering user-driven
`Send_Ping` + the inbound-Pong drop path; `Transport_Type` made
`Limited_Controlled` with a never-raise `Finalize` that dispatches to
`Close`, reclaiming abandoned standalone transports +
`test_transport_finalize`; on top of
`AHT.Transport.TLS` wired into both clients: `https://` in
`AHT.HTTP.Client` and `wss://` in `AHT.Websocket.Client`, each
threading `Insecure` / `CA_Path` into the handshake; TLS-wrapped WS
echo fixture `server_ws_tls.py` on :8768 + `test_ws_tls`).

## Task list (from the plan)

| # | Task | Status |
|---|---|---|
| 1 | Project skeleton (`alire.toml`, `aht.gpr`, empty specs) | done |
| 2 | `AHT.Bytes`, `AHT.URL`, `AHT.URL.Encoding` | done |
| 3 | `AHT.HTTP` shared types (Methods, Status, Headers) | done |
| 4 | `AHT.Transport` + `AHT.Transport.TCP` | done; `Connect` takes a `Connect_Timeout` (one total budget shared across all DNS candidates, raising `Timeout_Error` on exhaustion; `Duration'Last` = unbounded) |
| 5 | `AHT.Log` (level/subsystem facade + `Tag` generic child) | done |
| 6 | `AHT.HTTP.IO` (line reader, chunked decode) | done |
| 7 | Transport deadline/abort retrofit | done |
| 8 | `AHT.HTTP.Request` / `Response` / `Cancel` / streaming / `Client` | done over HTTP **and HTTPS**: sync `Send` / `Get`, sync `Send + Cancel_Handle`, `Send_Streaming` (with and without `Cancel_Handle`), buffered `Send_Async` / `Await` / `Cancel`. `https://` dispatches to `AHT.Transport.TLS` (threading `CA_Path` / `Insecure`). **Not in v1**: streaming async (`Send_Streaming_Async`). |
| 9 | mbedTLS fetch + build script + gpr wiring | done (`fetch_mbedtls.sh` fetches v2.28.9, SHA-256-verifies, extracts, and `make lib`s with threading; `regen_mbedtls_bindings.sh` runs `gcc -fdump-ada-spec` into `scratch/`; link wiring is `pragma Linker_Options` in `aht-mbedtls.ads` so only binaries that `with` it pull in the three archives + pthread) |
| 10 | `AHT.Mbedtls` bindings (generate + curate) | done (root `aht-mbedtls.ads`, `version`, plus the curated SSL / CTR_DRBG / Entropy / X509 / `error` surface `AHT.Transport.TLS` uses; contexts are opaque, allocated/freed by the C glue `csrc/aht_mbedtls_glue.c`. No NetSockets binding — byte I/O stays on the TCP transport via custom BIO) |
| 11 | `AHT.Transport.TLS` | done at the transport level (custom BIO over `AHT.Transport.TCP`: handshake, CA verify / `Insecure`, SNI, read/write with `WANT_*` retry, exception-isolating BIO callbacks; `Set_Read_Deadline`/`Abort_Pending` forward to TCP) **and wired into `AHT.HTTP.Client` for `https://`** and **`AHT.Websocket.Client` for `wss://`** (scheme dispatch threads `Insecure` / `CA_Path` into the handshake). All planned TLS client wiring is done |
| 12 | `AHT.Websocket.Frames` codec | done (direction-neutral encode + decode with masking, 7/16/64-bit lengths, control-frame validation including Close-payload structural + code-range checks, RSV-bit rejection, incomplete-buffer signalling; `Classify_Inbound_Close` applies the §7.4.1/§8.1 inbound close policy Decode defers) |
| 13 | `AHT.Websocket.Client` (receiver task + POs) | done for `ws://` **and `wss://`** — receiver task with frame reassembly + auto-Pong + RFC 6455 §1.4 close handshake on top of Send_Guard / Inbox / State POs; Send_Text / Send_Binary / Send_Ping / Receive / Close all wired; `Connect` dials TCP for `ws://`, TLS for `wss://` (one inline transport per scheme, `Active` points at the dialed one). Inbound text payloads are validated as UTF-8 (RFC 3629); ill-formed text fails the connection with close code 1007 (RFC 6455 §8.1) |
| 14 | Python test servers + cert generation | done (plain HTTP, plain WS, HTTPS `server_tls.py`, a silent `server_stall.py` fixture on :8767 for the handshake-timeout test, and a TLS-wrapped WS echo `server_ws_tls.py` on :8768; `scripts/generate_cert.sh` produces a self-signed cert with `localhost` + `127.0.0.1` SANs, regenerated each run) |
| 15 | Ada integration tests + `run_tests.sh` | done for HTTP + HTTPS + plain WS + WS-over-TLS + mbedTLS smoke + TLS transport + TLS handshake timeout + WS UTF-8 validator (26 tests; orchestrator creates a venv on first run, installs the requirements, generates the cert, brings up all five fixtures, and runs all binaries) |

## What's built and tested

- `alr build` produces `lib/libaht.a` cleanly.
- Unit tests all pass:
  - `tests/bin/test_url` — scheme dispatch, IPv6 literals, userinfo,
    default/custom ports, `To_String` round trip.
  - `tests/bin/test_url_encoding` — unreserved-byte pass-through,
    non-ASCII percent encoding (Latin-1 `é` → `%E9`), form encoding
    (`+` for space), round trips, invalid-escape error.
  - `tests/bin/test_headers` — case-insensitive `Set`/`Contains`/`Get`,
    `Set` replaces, `Append` preserves repeats, `Values` returns each
    value individually (no lossy comma-join).
  - `tests/bin/test_tcp` — in-process Ada echo server on 127.0.0.1:
    `Connect` → `Write` → `Read` → clean EOF → `Close`. Ten cases:
    literal, DNS, `[bad,good]` multi-addr fallback, `[bad,bad]`
    all-fail / last-error-wins, `Abort_Pending` unblocks a parked
    `Read` (sibling task, < 1 s to `Aborted_Error`),
    `Set_Read_Deadline (0.1)` fires `Timeout_Error` (0.05–1 s),
    compound-deadline semantics — after `Set_Read_Deadline (0.1)` +
    `delay 0.25`, `Read` raises within 0.05 s rather than granting
    a fresh budget — and three `Connect_Timeout` cases: a refusal
    under a generous budget still raises `Transport_Error` (not
    misclassified as a timeout), `[bad,good]` fallback survives a
    budget, and a `0.0` (exhausted) budget raises `Timeout_Error`
    before any dial.
  - `tests/bin/test_transport_finalize` — fixture-free unit test of
    `Transport_Type`'s inherited `Finalize`, using an in-process test
    double whose `Close` bumps a counter (and optionally raises).
    Three cases: a transport that leaves scope without an explicit
    `Close` has `Close` dispatched once by `Finalize`; a `Close` that
    raises is swallowed so no exception escapes the scope exit; and an
    explicit `Close` followed by scope-exit `Finalize` drives `Close`
    twice (the idempotent-`Close` contract `Finalize` relies on).
  - `tests/bin/test_log` — silent default, captured-record sink,
    global + per-subsystem level filtering, concurrent emit through
    `Synchronized_Sink` (800 bumps, zero lost).
  - `tests/bin/test_http_wire` — mock-transport unit test of the
    request/response wire codec. Sixteen cases: GET with no body
    (no auto Content-Length, final CRLFCRLF present), POST with a
    body (auto Content-Length = `Body_B'Length`, body follows the
    head separator), caller-supplied `Transfer-Encoding` on a
    request raises `Protocol_Error` (v1 doesn't do chunked
    uploads), Content-Length response, chunked response
    reassembled, read-until-EOF fallback when no framing header is
    present, `Protocol_Error` on non-numeric Content-Length /
    out-of-range status / malformed header line, a valid status
    line with an empty reason phrase (`HTTP/1.1 204`), 101
    Switching Protocols leaves post-header bytes on the wire (WS
    upgrade case), 204 with no framing header doesn't spin into
    the EOF fallback, 204 with an erroneous `Content-Length: 5 +
    body` ignores the CL and leaves the body bytes on the wire
    (RFC 7230 §3.3.3), 205 Reset Content with erroneous
    `Content-Length: 4 + body` does the same (RFC 9110 §15.3.6),
    304 with erroneous `Transfer-Encoding: chunked` does not
    invoke the chunked decoder, and HEAD with an erroneous
    `Content-Length: 1234 + NEXTRESP` leaves the trailing bytes
    on the wire (Method threaded into `Response.Read`).
  - `tests/bin/test_http_client` — in-process Ada HTTP/1.1 server
    + `AHT.HTTP.Client.Send`/`Get`. Seven cases: GET round-trip
    with the default `Host` / `User-Agent: AHT/0.1` / `Connection:
    close` headers verified on the wire; POST with body
    (auto Content-Length, body bytes forwarded, response body
    returned); HEAD against a peer that advertises `Content-Length:
    9999` but sends no body (completes in <1.5 s, body empty);
    interim 100 Continue → 200 loop returns the 200; 500
    Internal Server Error returned as `Resp.Status`, not raised;
    `Default_Headers ["user-agent"] = "custom/9"` beats
    `Self.User_Agent` while an explicit `Connection: keep-alive`
    on the request beats the auto `Connection: close` default;
    `wss://` URL passed to `Send` raises `HTTP_Error`.

End-to-end integration suite against `tests/server/server.py`
(plain HTTP on 127.0.0.1:8764, started by `tests/run_tests.sh`):

  - `tests/bin/test_http_get` — GET `/hello`, asserts 200 +
    `text/plain` + body `"hello, world\n"`.
  - `tests/bin/test_http_chunked` — GET `/chunked` (three uneven
    chunks `"AHT "`, `"rocks"`, `"!\n"`), asserts the decoder
    reassembles them to `"AHT rocks!\n"` and that no
    `Content-Length` leaks into the response headers.
  - `tests/bin/test_http_post` — POST `/echo` with a
    form-urlencoded body; asserts the server echoes the body and
    the round-tripped `Content-Type`.
  - `tests/bin/test_http_auth` — GET `/protected` without
    `Authorization` → 401 with `WWW-Authenticate`; same URL with
    `Authorization: Bearer …` → 200 echoing the header value
    verbatim (so a server that flipped on header presence alone
    wouldn't pass — the echo proves AHT actually transmitted the
    value).

`tests/run_tests.sh` builds the library and tests, starts the
fixture (waiting on the `READY` line for sync, killing it on
exit), runs every binary in `tests/bin/`, and reports
pass/fail.

In-process Ada-only test of the cancel surface:

  - `tests/bin/test_http_cancel` — four cases against in-process
    Ada server tasks. (1) **Cancel during a blocked Read**: a
    silent server holds the TCP connection without writing; a
    sibling task fires `Cancel` after 200 ms; `Send` raises
    `Aborted_Error` in well under the 1.5 s safety window, and
    `Is_Cancelled` reflects the call. (2) **Pre-cancel**: handle
    is cancelled *before* `Send`; the call raises immediately
    against `http://127.0.0.1:1/never` and stays under 0.5 s,
    proving the short-circuit happens before any connect attempt.
    (3) **Post-Send cancel is a no-op**: a fast in-process server
    responds 200 quickly, `Send` returns normally, then `Cancel`
    on the now-unbound handle runs without raising (and
    `Is_Cancelled` flips to true). (4) **Fresh handle**:
    `Is_Cancelled` is false on a never-cancelled handle.

End-to-end WebSocket round-trip against the Python `websockets`
echo fixture (commit 2 of the WS client work):

  - `tests/bin/test_ws_echo` — seven cases. (1–5) Text +
    Binary round-trips, idle-connection `Receive` timeout
    surfacing `AHT.Transport.Timeout_Error`, `Receive` after
    `Close` raising `Closed_Error`, and three-message ordering.
    (6) **Single-use lifecycle**: after `Close`, a second
    `Connect` on the same `Client_Type` raises
    `Handshake_Error` upfront — no second TCP dial, no
    Tasking_Error from the one-shot receiver. (7) **Callback
    firing**: `Set_On_Message` + `Set_On_Close` install
    callbacks that fire from the receiver task. A round-trip
    + clean Close drives `On_Message` once (payload matches
    what was sent) and `On_Close` once. The push API runs
    alongside the pull `Receive`, so both modes see the
    message.

  - `tests/bin/test_ws_ping` — exercises user-driven `Send_Ping`
    against the same echo fixture. The `websockets` library
    auto-Pongs at the protocol layer and never surfaces the Ping to
    its handler, so the cases lean on two facts: a malformed control
    frame would make the server close with 1002 (so a clean round-trip
    after a ping proves a valid masked Ping went out), and the
    receiver drops inbound Pongs (so they must never appear as
    messages). Three cases: (1) empty ping then a text round-trip
    still succeeds and `Close` flips `Is_Open` false; (2) ping with a
    payload then a round-trip (control-frame payload through the
    masking path); (3) `Send_Text "before"` / `Send_Ping` /
    `Send_Text "after"` — both echoes return in order and a follow-up
    `Receive` times out, proving the auto-Pong hit the `Pong_Op =>
    null` drop branch instead of leaking as a phantom message and that
    the control frame did not corrupt the surrounding data framing.
  - `tests/bin/test_ws_tls` — the wss:// sibling of
    `test_ws_echo`, against the TLS-wrapped echo fixture
    `server_ws_tls.py` on 127.0.0.1:8768 (reusing the same
    self-signed cert as the HTTPS fixtures). Three cases,
    mirroring `test_http_tls`: (1) **verify** — `Connect` with
    `CA_Path` pointing at the fixture cert, a text round-trip,
    and a clean `Close` (`Is_Open` flips to False); (2)
    **insecure** — `Connect` with `Insecure => True`, a 16-byte
    binary round-trip through the masking / framing path; (3)
    **untrusted** — verify required with no CA, the self-signed
    chain is rejected and `Connect` propagates
    `AHT.Transport.TLS.TLS_Error` unwrapped (the TLS dial sits
    before the handshake's `Handshake_Error` wrapper). Proves
    the wss:// scheme dispatch threads `Insecure` / `CA_Path`
    into `AHT.Transport.TLS` and round-trips real frames.

WebSocket handshake integration test (commit 1 of the WS client
work — frame I/O landed in commit 2):

  - `tests/bin/test_ws_handshake` — eleven cases. (1) **RFC 4648
    §10 base64 vectors** ("" / "f" / "fo" / "foo" / "foob" /
    "fooba" / "foobar" → known outputs) — catches padding /
    index math before any network is involved. (2) **Successful
    handshake** against the `websockets`-library echo fixture on
    127.0.0.1:8765; `Is_Open` flips to True; explicit `Close`
    tears the transport down. (3) **Non-WS server**:
    `ws://127.0.0.1:8764/hello` (the plain HTTP fixture) returns
    200 → `Handshake_Error`. (4) **wss://** with `Insecure =>
    True` against the HTTPS-only fixture on 8766: the TLS dial
    succeeds but the non-101 upgrade response →
    `Handshake_Error`, proving the wss:// path reaches handshake
    validation (TLS round-trip itself is `test_ws_tls`). (5)
    **http://** scheme
    pointed at the WS port → `Handshake_Error` (must be ws://
    or wss://). (6) **Double Connect** on the same Client →
    `Handshake_Error` (single-use). (7) **Extra_Headers**: a
    benign extra header is forwarded, and an attempt to override
    `Sec-WebSocket-Key` via Extra_Headers is silently ignored —
    the handshake still succeeds because the client's
    internally-generated Key is what the server's Accept echoes.
    Cases 8–12 use an **in-process Ada "fake handshake server"**
    that reads the client's `Sec-WebSocket-Key`, computes the
    correct Accept (so the response is valid up to the
    subprotocol check), and emits a 101 with a test-controlled
    extra header line — and optionally a test-controlled chunk
    of post-handshake bytes (case 12 below). (8) **Unsolicited subprotocol** — server
    returns `Sec-WebSocket-Protocol: evil-proto` when the client
    offered none → `Handshake_Error`. (9) **Not-offered
    subprotocol** — client offers `good-proto-v1, good-proto-v2`
    but server selects `evil-proto` → `Handshake_Error`. (10)
    **Two Sec-WebSocket-Protocol header lines** (RFC §4.1 allows
    at most one) → `Handshake_Error`. (11) **Positive subprotocol
    negotiation** — client offers `aht.echo.v1, aht.echo.v2`,
    server picks `aht.echo.v1`; Connect succeeds and
    `Selected_Subprotocol` returns `"aht.echo.v1"`. (12)
    **Server sends a masked frame** post-handshake — RFC 6455
    §5.1 forbids server-side masking; the receiver task
    rejects it, marks the connection Closed, and `Receive`
    raises `Closed_Error` instead of delivering the "evil"
    payload. (13) **`Close (Timeout => 0.1)` honours the
    knob** — the fake server holds the socket silently for
    2 s after the handshake; `Close` falls through to
    `Abort_Pending` and returns in well under 0.5 s instead
    of waiting the default 5.0 s.

mbedTLS bind/link chain smoke test:

  - `tests/bin/test_mbedtls_version` — calls
    `AHT.Mbedtls.Version.Version_String` /
    `Full_Version_String`, asserts the runtime values match
    `"2.28.9"` / `"Mbed TLS 2.28.9"`, and cross-checks the
    compile-time `Major`/`Minor`/`Patch` constants. Exercises
    the `pragma Linker_Options` in `aht-mbedtls.ads`, the
    curated Imports of `mbedtls_version_get_string` /
    `_full`, and the `char_array` ↔ Ada `String` round-trip.

Transport-level TLS test against the HTTPS fixture
(`tests/server/server_tls.py` on 127.0.0.1:8766):

  - `tests/bin/test_tls` — drives `AHT.Transport.TLS` by speaking a
    minimal HTTP/1.1 `GET /hello` over the established session (no HTTP
    client involved). Three cases: (1) **verify** — `CA_Path` points at
    the fixture's self-signed cert, the handshake succeeds (chain +
    `localhost` SAN match) and `/hello` echoes back; (2) **insecure** —
    `Insecure => True` with no CA still completes and serves `/hello`;
    (3) **untrusted** — `VERIFY_REQUIRED` with no CA configured rejects
    the self-signed chain with `TLS_Error`. Exercises the custom BIO
    callbacks, opaque-context allocation, and the read-to-clean-EOF
    path end to end.

  - `tests/bin/test_http_tls` — the same three cases (verify /
    insecure / untrusted) driven through `AHT.HTTP.Client.Get` over
    `https://localhost:8766/hello` instead of the raw transport,
    proving the `https://` scheme dispatch threads `Client_Type.CA_Path`
    / `.Insecure` into the handshake and round-trips a parsed
    `Response_Type`.

  - `tests/bin/test_tls_timeout` — drives the handshake-timeout path
    against `server_stall.py` (127.0.0.1:8767), which accepts the TCP
    connection but never sends a ServerHello. Two cases: (1)
    transport-level `TLS.Connect` with `Handshake_Deadline => 1.0`
    raises `Timeout_Error` instead of hanging; (2) `AHT.HTTP.Client.Get`
    with `Timeout_Seconds => 1` does the same, proving the client
    threads its timeout into `Connect`'s `Handshake_Deadline`. Both
    assert the wait stayed within a generous bound, so a regression
    that ignored the deadline would surface as a hang/over-budget.
    The sibling *TCP-connect* budget (`Connect_Timeout`) is covered
    deterministically by `test_tcp` cases 8–10 (refusal-under-budget,
    fallback-under-budget, exhausted-budget → `Timeout_Error`) without
    a network fixture. Only a genuine mid-connect stall — a peer that
    accepts the SYN but never finishes `connect()`, i.e. the
    `Connect_Socket` `Status = Expired` line — is left untested, since
    it needs an unroutable/firewalled address too environment-dependent
    for CI; case 10 reaches the same `Timeout_Error` via the
    pre-attempt budget check instead.

Pure unit test of the WS framing codec (no sockets — works
entirely over `Byte_Array` / `Byte_Vector`):

  - `tests/bin/test_ws_frames` — 29 cases covering (1–2) byte-
    exact RFC 6455 §5.7 encode vectors (unmasked + masked
    "Hello"), (3–4) §5.7 decode vectors, (5–6) round-trip 200-
    and 70 000-byte masked frames (exercising the 2- and 8-byte
    extended-length paths), (7) empty masked Ping → exact
    `89 80 11 22 33 44`, (8) fragmented decode (Text/Continuation
    back-to-back, advancing `Last`), (9) five incomplete-buffer
    boundaries → `Last = 0` without raising, (10) reserved
    opcode 0x3 → `Protocol_Error`, (11) control frame with
    `FIN = 0` → `Protocol_Error`, (12) oversized control frame
    → `Protocol_Error`, (13) non-minimal length encoding →
    `Protocol_Error`, (14) `RSV1` set → `Protocol_Error`, (15)
    outbound fragmented Close `Encode` → `Protocol_Error`,
    (16) Close with empty payload and Close with `1000`+reason
    both encode successfully, (17) Close `Encode` with 1-byte
    payload → `Protocol_Error` (RFC §5.5.1), (18) Close `Encode`
    with synthetic code 1005 → `Protocol_Error` (`Valid_Close_Code`
    excludes 1004/1005/1006/1015), (19) Close `Encode` with
    out-of-range code 999 → `Protocol_Error`, (20) Decode a
    normal Close with code 1000 succeeds, (21) Decode a Close
    with 1-byte payload → `Protocol_Error`, (22) Decode a Close
    with out-of-range code 999 → `Protocol_Error`, (23) Decode
    accepts a Close with code 1006 (`Any_Close_Code` covers the
    synthetic codes as inbound observations — the Client layer
    decides what to do with them), (24) Close `Encode` with
    reserved code 1004 → `Protocol_Error` (must never be sent),
    (25–29) `Classify_Inbound_Close`: empty payload and
    `1000`+reason → `Accept_Close`, each reserved code
    1004/1005/1006/1015 → `Reserved_Code`, `1000`+lone-`0x80`
    reason → `Bad_Reason`, `1000`+valid multi-byte reason
    (`C3 A9`) → `Accept_Close`.

Pure unit test of the RFC 3629 UTF-8 validator (no sockets — a
predicate over `Byte_Array` / `Byte_Vector`, the check a WebSocket
endpoint applies to inbound text payloads before accepting them):

  - `tests/bin/test_ws_utf8` — 30 cases over both `Is_Valid`
    overloads, drawn from the Autobahn|Testsuite §6 cases and
    Markus Kuhn's UTF-8 stress suite. Valid: empty, ASCII, NUL,
    the canonical "κόσμε", and the RFC 3629 Table 3-7 code-point
    boundaries (U+007F / 0080 / 07FF / 0800 / FFFF / 10000 /
    10FFFF-max). Invalid: lone / truncated continuations, an extra
    continuation byte, overlong encodings (`c080` / `c0af` /
    `e08080` / `f0808080`), UTF-16 surrogate halves (`eda080` /
    `edbfbf`), values above U+10FFFF (`f4908080`), illegal start
    bytes (`f5` / `c0` / `c1` / `ff`), the forbidden 5-byte form,
    and the exact Autobahn 6.3.1 payload (κόσμε + a surrogate +
    "edited"). A regression here maps straight to an Autobahn §6
    failure.

End-to-end test of the async surface (mixes the Python fixture
with one in-process silent server for the cancel case):

  - `tests/bin/test_http_async` — eight cases. (1) **Happy path**:
    `Send_Async` to `/hello`, `Await` returns 200 with body; the
    handle reports `Is_Done`. (2) **Concurrent**: two handles,
    two `Send_Async`s (one to `/hello`, one to `/json`), both
    `Await`s yield the expected body. (3) **Cancel before
    Await**: silent in-process server; main task `Cancel`s after
    200 ms; `Await` re-raises `Aborted_Error` with original
    identity in <1.5 s and both `Is_Cancelled` and `Is_Done` are
    true. (4) **Double Send_Async**: second `Send_Async` on a
    started handle raises `HTTP_Error`. (5) **Drop without
    Await**: handle is `Send_Async`'d in an inner declare block;
    block ends without `Await` — the worker has already
    terminated (it stashes the result in the protected state and
    exits), so the scope exits in under 2 s. (6) **Exception
    identity round-trip**: `wss://` URL routed to `Send`
    produces `HTTP_Error`; `Await` re-raises that exact
    exception (`Save_Occurrence` /  `Reraise_Occurrence` preserves
    identity), not a generic wrapper. (7) **Await before
    Send_Async raises**: calling `Await` on a fresh, never-Sent
    handle returns `HTTP_Error` in well under 0.5 s instead of
    deadlocking on the worker's Start rendezvous. (8) **Double
    Await is replayable**: after a successful first Await, a
    second Await on the same handle returns the same response in
    under 0.1 s (pure Read_Result from the protected state, no
    rendezvous, the worker is already gone).

End-to-end test of the streaming surface (uses both the Python
fixture and two in-process server tasks for the cancel /
sink-raise cases):

  - `tests/bin/test_http_streaming` — five cases. (1) **Chunked
    streaming**: GET `/chunked`, sink receives the decoded
    chunks one at a time, assembled bytes match `"AHT rocks!\n"`,
    and `Resp.Body_B` is empty after — proves the sink is the
    sole owner of the body. (2) **Content-Length streaming**:
    GET `/hello`, sink delivers `"hello, world\n"` (one or more
    calls), `Resp.Body_B` empty. (3) **Cancel during streaming**:
    silent in-process server; sibling task fires `Cancel`;
    `Send_Streaming` raises `Aborted_Error` in <1.5 s and the
    sink was never invoked. (4) **Sink exception propagates**:
    fast in-process server sends a body; sink raises on the first
    call; the exception comes out of `Send_Streaming`. (5)
    **Recovery from sink raise**: a follow-up `Send_Streaming`
    against a fresh server completes normally, proving the
    transport-close-on-exception path doesn't poison subsequent
    calls.
  - `tests/bin/test_http_io` — mock-transport unit test of HTTP.IO:
    `Write_All` forwards bytes (empty is a no-op); `Read_Line`
    returns status / header lines without CRLF and leaves the
    transport at the next byte, raises `Protocol_Error` on EOF
    before CRLF and past `Max_Length`; `Read_N` fills across
    `Chunk_Size = 1` reads and raises on short stream;
    `Read_Chunked_Body` reassembles multi-chunk bodies, ignores
    `chunk-ext`, accepts upper-case hex, drains trailer headers,
    and raises on non-hex size or missing post-data CRLF.

## WebSocket conformance (Autobahn|Testsuite)

A dockerized Autobahn `fuzzingserver` harness lives in
`tests/autobahn/` (kept out of `run_tests.sh` — it needs Docker and is
run on demand). `tests/autobahn/run.sh` brings up the
`crossbario/autobahn-testsuite` image (`--network host`, custom
`--webport` to dodge the :8080 UI collision) and drives the
`aht_autobahn` testee (`tests/autobahn/src/aht_autobahn.adb`) against
all ~517 RFC 6455 client cases — `/getCaseCount`, then `/runCase` for
each (echoing every data message), then `/updateReports`. Reports land
in `tests/autobahn/reports/`. The testee is built once as a developer
step (`autobahn.gpr`, deliberately not in `tests.gpr`); the script only
checks the binary exists, so it runs cleanly under `sudo` where `alr`
is not on `PATH`.

Current standing: sections 1–5 (framing, ping/pong, reserved bits,
opcodes, fragmentation) pass at 100%. §6 (UTF-8) passes once the
validator landed — all 145 cases clear (141 OK + 4 NON-STRICT, 0
FAILED), where 75 of them failed before the fix. §7 (close handshake)
now passes too: `Frames.Classify_Inbound_Close` applies the inbound
policy Decode defers, so a received reserved code (1004/1005/1006/1015,
RFC §7.4.1) fails the connection with 1002 and a non-UTF-8 close reason
(RFC §8.1) fails with 1007 — cases 7.5.1 / 7.9.3 / 7.9.4 / 7.9.5 flipped
to OK. §12/§13 (permessage-deflate) report UNIMPLEMENTED, which is
expected: AHT does not negotiate that extension. Remaining FAILED is §9
large-payload throughput only — 11 cases (9.1.4/5/6, 9.2.3/4/5/6,
9.3.8/9, 9.4.8/9) at 1–16 MB time out, tracked as a separate follow-up
slice. Latest full run: 282 OK, 5 NON-STRICT, 3 INFORMATIONAL, 216
UNIMPLEMENTED, 11 FAILED.

### Deferred follow-ups (revisit later)

Two items came out of the §7 review/work that are intentionally left
for their own slices:

1. **Decode-rejected closes should also reply 1002.** The §7 slice
   handles a *successfully decoded* Close frame whose code/reason
   violate policy (`Classify_Inbound_Close`). But when a Close frame
   fails to decode at all (a `Protocol_Error` out of
   `Frames.Decode` — e.g. a malformed/over-long control frame), the
   receiver's exception handler in `Handle_Receive` (client.adb, the
   Protocol_Error/Transport branch) only fires `On_Error` + stops the
   loop; it does **not** send a 1002 Close before tearing down. The
   broader fix is "on any decode `Protocol_Error`, send 1002 then
   close". Cases 7.9.1/2/6 already pass today by dropping the
   connection, so this is correctness/politeness, not a current
   Autobahn failure.

2. **§9 large-payload throughput is O(N²), corrected diagnosis.** The
   receive path keeps the inbound bytes in an `AHT.Bytes.Byte_Vector`
   (`Ada.Containers.Vectors` of `Octet`). The dominant cost is the
   per-frame `Stream.Delete_First` loop that shifts the whole buffer
   down one element at a time after each successful `Decode`; the
   secondary cost is re-running `Vector_To_Array (Stream, Have)` over
   the entire unconsumed buffer on every loop turn. (Decode itself
   `Reserve_Capacity`s the payload, so payload *assembly* is linear,
   and Decode bails on incomplete input before touching payload bytes,
   so there is no payload reparse — my earlier "reparses from byte 0"
   framing was wrong.) Fix: replace the `Byte_Vector` with an
   index-managed `Byte_Array`/`Stream_Element_Array` plus a consumed
   cursor, parse the header/length in place, compact lazily, and do
   bulk slice copies (inbound is unmasked — servers MUST NOT mask — so
   the payload copy is a clean block move). Must preserve interleaved
   control-frame handling and reserve `Reassembly_Buf` before
   continuation appends.

## Review findings — resolved

From the first code review of the foundational layer:

1. IPv6 URL parsing broken → authority parser now handles `[...]`.
2. `Percent_Encode` treated non-ASCII letters as unreserved →
   ASCII-only `Is_Unreserved`; spec documents the byte-oriented
   contract.
3. Close-code subtype allowed forbidden 1005/1006/1015 on outbound →
   split into `Any_Close_Code` (received) and `Valid_Close_Code`
   (sent); `On_Close_Callback` takes a `Close_Info (Has_Code : Boolean)`
   so no-code closes are representable.
4. `Get_All` joined every repeat with `", "` → removed; replaced by
   `Values` returning a `Value_List`, so `Set-Cookie` round-trips
   correctly.

Userinfo is now parsed into `URL_Type.User_Info` (exposed, not
auto-injected as `Authorization`). Encoding spec states that inputs
are treated as byte sequences (UTF-8 is caller's responsibility).

## What's next

The TLS transport (task 11) has landed and is wired into both clients:
`https://` in `AHT.HTTP.Client` (with `test_http_tls`) and `wss://` in
`AHT.Websocket.Client` (with `test_ws_tls`). `Connect` dials TCP for
`ws://` and TLS for `wss://`, threading `Insecure` / `CA_Path` into the
handshake. All planned TLS client wiring is now done.

Cross-cutting lifecycle change (landed in its own commit, separate
from TLS bring-up): `Transport_Type` now derives from
`Ada.Finalization.Limited_Controlled` with a best-effort, never-raise
`Finalize` that dispatches to `Close`, so an abandoned standalone
`TCP_Transport` / `TLS_Transport` is reclaimed deterministically
(`test_transport_finalize` covers the dispatch + swallow branches).
This closes the leak for plain transport objects only — it does
**not** solve abandonment of higher-level owners that also have a task
to join (notably `Websocket.Client`'s receiver task), which still
requires an explicit `Close`.

Possible follow-ups that didn't make v1: HTTP
`Send_Streaming_Async` (buffered async is here; streaming async
wasn't worth the extra surface vs. "spawn your own task that
calls `Send_Streaming`"), re-usable `Async_Handle` (currently
single-use).
