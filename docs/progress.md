# Progress

Snapshot of implementation status against [`plan.md`](plan.md).
Last updated: 2026-04-22.

## Task list (from the plan)

| # | Task | Status |
|---|---|---|
| 1 | Project skeleton (`alire.toml`, `aht.gpr`, empty specs) | done |
| 2 | `AHT.Bytes`, `AHT.URL`, `AHT.URL.Encoding` | done |
| 3 | `AHT.HTTP` shared types (Methods, Status, Headers) | done |
| 4 | `AHT.Transport` + `AHT.Transport.TCP` | done |
| 5 | `AHT.Log` (level/subsystem facade + `Tag` generic child) | done |
| 6 | `AHT.HTTP.IO` (line reader, chunked decode) | stubbed |
| 7 | Transport deadline/abort retrofit | done |
| 8 | `AHT.HTTP.Request` / `Response` / `Cancel` / streaming / `Client` | stubbed |
| 9 | mbedTLS fetch + build script + gpr wiring | stubbed (placeholder script) |
| 10 | `AHT.Mbedtls` bindings (generate + curate) | not started |
| 11 | `AHT.Transport.TLS` | stubbed |
| 12 | `AHT.Websocket.Frames` codec | stubbed |
| 13 | `AHT.Websocket.Client` (receiver task + POs) | stubbed |
| 14 | Python test servers + cert generation | not started |
| 15 | Ada integration tests + `run_tests.sh` | partial (5 tests, no run_tests.sh yet) |

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
    `Connect` → `Write` → `Read` → clean EOF → `Close`. Six cases:
    literal, DNS, `[bad,good]` multi-addr fallback, `[bad,bad]`
    all-fail / last-error-wins, `Abort_Pending` unblocks a parked
    `Read` (sibling task, < 1 s to `Aborted_Error`), and
    `Set_Read_Deadline (0.1)` fires `Timeout_Error` (0.05–1 s).
  - `tests/bin/test_log` — silent default, captured-record sink,
    global + per-subsystem level filtering, concurrent emit through
    `Synchronized_Sink` (800 bumps, zero lost).

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

1. `AHT.HTTP.IO` — CRLF line reader, `Write_All`, chunked decoder.
   Uses `AHT.Log.Tag ("http.io")`.
2. `AHT.HTTP.Request` / `Response` / `Cancel_Handle` / `Body_Reader`
   / `Response_Stream` / `Request_Handle` / `Client` — serialize
   request, parse response, build the streaming core, layer the
   three surfaces (sync / streaming / async with cancel). The core
   plumbs `Cancel_Handle` to `Transport.Abort_Pending`, now wired.
3. Python plain-HTTP test server + integration tests for GET,
   chunked, POST, auth, streaming, cancel, async.
4. Real `scripts/fetch_mbedtls.sh` + `scripts/regen_mbedtls_bindings.sh`
   (`gcc -fdump-ada-spec` over mbedTLS 2.28.9 headers, curated into
   `src/`).
5. `AHT.Transport.TLS` + HTTPS integration test. Overrides
   `Abort_Pending` by aborting the underlying TCP selector.
6. `AHT.Websocket.Frames` RFC 6455 codec (unit-testable without
   sockets).
7. `AHT.Websocket.Client` — receiver task, `Send_Guard`, `Inbox`,
   `State` POs; reuse `AHT.HTTP.*` for the upgrade.
8. Python WS / WSS servers + WebSocket integration tests.
9. `tests/run_tests.sh` orchestrating venv, servers, build, and
   binaries.
