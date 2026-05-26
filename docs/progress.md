# Progress

Snapshot of implementation status against [`plan.md`](plan.md).
Last updated: 2026-05-26 (Python HTTP fixture + integration tests).

## Task list (from the plan)

| # | Task | Status |
|---|---|---|
| 1 | Project skeleton (`alire.toml`, `aht.gpr`, empty specs) | done |
| 2 | `AHT.Bytes`, `AHT.URL`, `AHT.URL.Encoding` | done |
| 3 | `AHT.HTTP` shared types (Methods, Status, Headers) | done |
| 4 | `AHT.Transport` + `AHT.Transport.TCP` | done |
| 5 | `AHT.Log` (level/subsystem facade + `Tag` generic child) | done |
| 6 | `AHT.HTTP.IO` (line reader, chunked decode) | done |
| 7 | Transport deadline/abort retrofit | done |
| 8 | `AHT.HTTP.Request` / `Response` / `Cancel` / streaming / `Client` | partial (sync `Client.Send`/`Get` done over HTTP; HTTPS, Cancel, streaming, async to come) |
| 9 | mbedTLS fetch + build script + gpr wiring | stubbed (placeholder script) |
| 10 | `AHT.Mbedtls` bindings (generate + curate) | not started |
| 11 | `AHT.Transport.TLS` | stubbed |
| 12 | `AHT.Websocket.Frames` codec | stubbed |
| 13 | `AHT.Websocket.Client` (receiver task + POs) | stubbed |
| 14 | Python test servers + cert generation | partial (plain HTTP fixture done; TLS / WS servers + certs to come) |
| 15 | Ada integration tests + `run_tests.sh` | done for HTTP (12 tests; orchestrator brings up the fixture and runs all binaries) |

"Stubbed" = spec is final, body compiles and raises a
Not-Implemented exception if called.

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
    `Connect` → `Write` → `Read` → clean EOF → `Close`. Seven cases:
    literal, DNS, `[bad,good]` multi-addr fallback, `[bad,bad]`
    all-fail / last-error-wins, `Abort_Pending` unblocks a parked
    `Read` (sibling task, < 1 s to `Aborted_Error`),
    `Set_Read_Deadline (0.1)` fires `Timeout_Error` (0.05–1 s), and
    compound-deadline semantics — after `Set_Read_Deadline (0.1)` +
    `delay 0.25`, `Read` raises within 0.05 s rather than granting
    a fresh budget.
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
  - `tests/bin/test_http_io` — mock-transport unit test of HTTP.IO:
    `Write_All` forwards bytes (empty is a no-op); `Read_Line`
    returns status / header lines without CRLF and leaves the
    transport at the next byte, raises `Protocol_Error` on EOF
    before CRLF and past `Max_Length`; `Read_N` fills across
    `Chunk_Size = 1` reads and raises on short stream;
    `Read_Chunked_Body` reassembles multi-chunk bodies, ignores
    `chunk-ext`, accepts upper-case hex, drains trailer headers,
    and raises on non-hex size or missing post-data CRLF.

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

In the order the plan specifies:

1. `Cancel_Handle` / streaming / async surfaces of task 8 on top
   of the existing sync `Client.Send`. Cancel maps to
   `Transport.Abort_Pending` (already wired and tested in
   `test_tcp`); streaming/async layer on top of the shared sync
   core.
2. Real `scripts/fetch_mbedtls.sh` + `scripts/regen_mbedtls_bindings.sh`
   (`gcc -fdump-ada-spec` over mbedTLS 2.28.9 headers, curated into
   `src/`).
3. `AHT.Transport.TLS` + HTTPS wiring in `Client.Send` + HTTPS
   integration test. `Transport.TLS.Abort_Pending` aborts the
   underlying TCP selector. Will need `tests/server/server_tls.py`
   and `tests/server/generate_cert.sh` (the orchestrator can take
   on a venv step there if pip deps appear).
4. `AHT.Websocket.Frames` RFC 6455 codec (unit-testable without
   sockets).
5. `AHT.Websocket.Client` — receiver task, `Send_Guard`, `Inbox`,
   `State` POs; reuse `AHT.HTTP.*` for the upgrade (the 101
   carve-out in the 1xx loop is in place).
6. Python WS / WSS servers + WebSocket integration tests; pin
   `websockets>=12.0` in `tests/server/requirements.txt` and
   teach `run_tests.sh` to create the venv.
