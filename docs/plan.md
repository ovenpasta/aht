# Ada HTTP + WebSocket Client Library — Implementation Plan

## Context

We are building a new Ada
**HTTP/HTTPS + WebSocket** client library (RFC 6455 for WS, RFC 7230 for
HTTP/1.1) that uses Ada's native concurrency primitives (tasks and
protected objects), supports TLS via mbedTLS **v2.28.9** (LTS), and is
exercised end-to-end by a Python test server.

User-confirmed decisions and preferences:
- Library ships **two** clients on a shared foundation: a general HTTP/1.1
  client and a WebSocket client. WebSocket reuses HTTP for the upgrade.
- Layered, extensible structure: separate modules for URL parsing,
  percent encoding, HTTP headers, HTTP messages, transport, WS framing, etc.
  Every module is independently testable.
- **Contracts where feasible**: subtype predicates, `Type_Invariant`,
  `Pre`/`Post` on public APIs — not comments.
- Concurrency via tasks + protected objects where async I/O makes it
  natural (notably the WS receiver loop); the HTTP client is
  synchronous-per-call but reentrant.
- mbedTLS: fetched as a tarball at build time (checksum-verified), built
  locally. Bindings generated in a scratch area with
  `gcc -fdump-ada-spec` and curated into the tree — never hand-written.
- Build: Alire crate + `gprbuild`, launched via `alr build`.
- Receive API for WebSocket: both callback (push) and blocking `Receive`
  (pull).
- v1 scope (WS): text + binary, auto ping/pong, clean close handshake,
  fragmentation. (HTTP): `GET`/`POST`/`PUT`/`DELETE`/`HEAD` with
  `Content-Length` bodies and chunked transfer decoding.

The crate is named `aht` and the Ada root namespace is **`AHT`** because
the library is broader than WebSockets alone. Every Ada unit is rooted
at `AHT.*` (e.g. `AHT.HTTP.Client`, `AHT.Websocket.Client`, `AHT.URL`,
`AHT.Transport`).

## Architecture — layered module map

```
                    ┌────────────────────────┐
                    │   AHT.Websocket.Client│  ← receiver task, inbox,
                    │   AHT.Websocket.Frames│    send-guard, state PO
                    └───────────┬─────────────┘
                                │ builds on HTTP upgrade
                    ┌───────────┴─────────────┐
                    │   AHT.HTTP.Client     │  ← synchronous HTTP/1.1
                    │   AHT.HTTP.Request    │    methods, chunked decode
                    │   AHT.HTTP.Response   │
                    │   AHT.HTTP.Headers    │  ← case-insensitive multimap
                    │   AHT.HTTP.Status     │  ← subtype predicate 100..599
                    │   AHT.HTTP.Methods    │
                    │   AHT.HTTP.IO         │  ← line reader, chunked codec
                    └───────────┬─────────────┘
                                │
                    ┌───────────┴─────────────┐
                    │   AHT.Transport       │  ← abstract Transport_Type'Class
                    │   AHT.Transport.TCP   │
                    │   AHT.Transport.TLS   │
                    └───────────┬─────────────┘
                                │
                    ┌───────────┴─────────────┐
                    │   AHT.Mbedtls.*       │  ← curated -fdump-ada-spec
                    └─────────────────────────┘

   AHT.URL         AHT.URL.Encoding       AHT.Bytes
   (parse/build)     (percent encode/decode)  (Byte_Array, subtypes)
        └────── used by all layers above ─────────────┘
```

### Units

| Unit | Role |
|---|---|
| `AHT` | Root: `Version` constant, project-wide exceptions. |
| `AHT.Bytes` | `Byte_Array is array (Positive range <>) of Interfaces.Unsigned_8`; helpers. |
| `AHT.URL` | `URL_Type` (record: scheme, host, port, path, query, fragment), `Parse`, `Build`, `To_String`. Subtype `Port_Number is Positive range 1 .. 65535`. |
| `AHT.URL.Encoding` | `Percent_Encode`/`Decode` (RFC 3986 unreserved set), `Form_Encode`/`Decode` (application/x-www-form-urlencoded). |
| `AHT.Transport` | Tagged abstract `Transport_Type` with `Read`, `Write`, `Close`, `Is_Connected`. |
| `AHT.Transport.TCP` | `GNAT.Sockets` implementation. |
| `AHT.Transport.TLS` | mbedTLS implementation; wraps a TCP transport. |
| `AHT.Mbedtls` (+ children) | Curated bindings generated via `gcc -fdump-ada-spec`. |
| `AHT.HTTP` | Shared types, `HTTP_Error` exception. |
| `AHT.HTTP.Methods` | `Method_Type` enum (`GET`, `POST`, `PUT`, `DELETE`, `HEAD`, `PATCH`, `OPTIONS`) + `Image`. |
| `AHT.HTTP.Status` | `subtype Status_Code is Integer with Static_Predicate => Status_Code in 100 .. 599;` + `Reason_Phrase`. |
| `AHT.HTTP.Headers` | Case-insensitive multimap: `Set`, `Append`, `Get`, `Get_All`, `Contains`, iteration. `Type_Invariant` that no name is empty and all names are normalized lowercase. |
| `AHT.HTTP.Request` | `Request_Type` record; setters for method/URL/headers/body. |
| `AHT.HTTP.Response` | `Response_Type` record: status, headers, body (`Byte_Vector`). |
| `AHT.HTTP.IO` | Transport-level helpers: `Read_Line` (CRLF-terminated, bounded), `Read_N_Bytes`, `Write_All`, chunked-transfer decoder. |
| `AHT.HTTP.Client` | `Client_Type` (tagged). Methods: `Get`, `Post`, `Send (Request, Response)`. Handles scheme dispatch (`http` → TCP, `https` → TLS), connection establishment, request serialization, response parsing (status line → headers → body via `Content-Length` or `Transfer-Encoding: chunked`). One request per call (no keep-alive in v1; `Connection: close`). Thread-safe: each call owns its transport. |
| `AHT.Websocket` | WS-specific types: `Opcode`, `Close_Code` (subtype predicate), `Message_Kind`. |
| `AHT.Websocket.Frames` | Pure codec: encode/decode frames, client masking, short/medium/extended lengths, control-frame validation. |
| `AHT.Websocket.Client` | High-level WS client: `Connect` (runs HTTP upgrade via `AHT.HTTP` primitives, then switches the transport to frame mode), `Send_Text/Binary/Ping`, `Close`, `Receive`, callback registration. |

### HTTP/HTTPS → WebSocket upgrade

`AHT.Websocket.Client.Connect` is implemented as:

1. `AHT.URL.Parse` — normalize `ws://`→`http://`, `wss://`→`https://`.
2. Establish a transport via the same path HTTP would (`AHT.Transport.TCP` or `AHT.Transport.TLS`).
3. Build a `AHT.HTTP.Request` with method `GET`, path + query, and headers: `Host`, `Upgrade: websocket`, `Connection: Upgrade`, `Sec-WebSocket-Version: 13`, `Sec-WebSocket-Key` (16 random bytes, base64), optional `Origin`, `Sec-WebSocket-Protocol`, plus any `Extra_Headers` passed by the caller.
4. Write request via `AHT.HTTP.IO`, read status line + headers via the same.
5. Validate `101 Switching Protocols`, `Upgrade`/`Connection` tokens (case-insensitive), `Sec-WebSocket-Accept` (SHA-1 of key + RFC GUID, base64).
6. Hand the now-open transport to the WS receiver task and `Send_Guard`.

Non-`101` responses (e.g. `401`, `403`, `404`) raise
`AHT.Websocket.Handshake_Error` with the HTTP status and reason so the
caller can distinguish auth failures from protocol errors.

### Concurrency model

- **HTTP client**: synchronous. Each `Send` call opens a transport, writes, reads, closes. No shared state beyond the `Client_Type`'s config (user agent, default headers, timeout, CA path). Multiple tasks can share one `Client_Type` because `Send` owns its transport for the call.
- **WebSocket client**:
  - `Receiver_Task` per connection reads frames, reassembles fragments, dispatches to callbacks and/or enqueues into `Inbox`.
  - `Send_Guard` protected object serializes writes (client frames must each carry a fresh 32-bit mask).
  - `Inbox` bounded FIFO with entry `Receive (Msg : out Message_Type; Timeout : Duration)` guarded by `Count > 0`.
  - `State` protected object: `Connecting | Open | Closing | Closed`; close is idempotent; `Client.Close` waits for receiver task termination.

### Contracts policy

Examples (non-exhaustive; every public type/subprogram is reviewed):

- `subtype Status_Code is Integer with Static_Predicate => Status_Code in 100 .. 599;`
- `subtype Close_Code is Natural with Dynamic_Predicate => Close_Code in 1000 .. 1015 or Close_Code in 3000 .. 4999;`
- `subtype Port_Number is Positive range 1 .. 65535;`
- `Type_Invariant` on `Headers.Map_Type` — internal name list is lowercase, non-empty.
- `Type_Invariant` on `Websocket.Client.Client_Type` — `State = Open` ⇒ transport allocated and receiver task not terminated.
- `Pre` on `Websocket.Client.Send_Text`: `Is_Open (Self)`.
- `Pre` on `URL.Build`: `U.Host'Length > 0`.
- `Post` on `URL.Parse`: `Result.Host'Length > 0 and Result.Port in Port_Number`.
- `Post` on `Frames.Encode`: `Output'Length >= 2 and Output'Length <= Payload'Length + 14`.
- `pragma Assertion_Policy (Check)` in debug builds, `Ignore` optional in release via gpr scenario variable.

## mbedTLS integration

- `scripts/fetch_mbedtls.sh` downloads `mbedtls-2.28.9.tar.bz2` from the
  Mbed-TLS GitHub release, verifies SHA-256 against a pinned value, extracts
  to `third_party/mbedtls-2.28.9/`, and runs `make lib` with
  `-DMBEDTLS_THREADING_C -DMBEDTLS_THREADING_PTHREAD`. Outputs static
  archives in `third_party/mbedtls-2.28.9/library/`.
- Alire pre-build action in `alire.toml` invokes the script so `alr build`
  is one step.
- `aht.gpr` adds the archives via `Linker_Options` for the TLS unit
  and links `-lpthread`.
- **Bindings are generated, not hand-written.** `scripts/regen_mbedtls_bindings.sh`:
  1. Creates `scratch/gen_bindings/`.
  2. Runs `gcc -c -fdump-ada-spec -C -fada-spec-parent=AHT.Mbedtls -I third_party/mbedtls-2.28.9/include third_party/mbedtls-2.28.9/include/mbedtls/{ssl,net_sockets,x509_crt,ctr_drbg,entropy,error}.h`.
  3. Operator copies the curated subset (`aht-mbedtls-ssl.ads`, `-x509_crt.ads`, `-net_sockets.ads`, `-ctr_drbg.ads`, `-entropy.ads`, `-error.ads`) into `src/`.
- A small hand-written body (`aht-mbedtls.adb`) maps non-zero `int` returns to a `AHT.Transport.TLS_Error` exception carrying the mbedTLS code (formatted via `mbedtls_strerror`).
- Certificate verification on by default (`MBEDTLS_SSL_VERIFY_REQUIRED`); `Insecure` parameter on `Transport.TLS.Connect` and `HTTP.Client.Send` downgrades for self-signed test certs.

## Python test server

- `tests/server/server.py` (Python `websockets` + built-in `http.server`)
  exposes:
  - WebSocket echo endpoint at `ws://127.0.0.1:8765/echo`.
  - HTTP endpoints at `http://127.0.0.1:8764/`: `/hello` (200 text),
    `/chunked` (200 chunked transfer), `/json` (200 application/json),
    `/redirect` (302 → `/hello`), `/protected` (401 unless
    `Authorization` header present, else echoes the header).
  - A second WS endpoint `/require-auth` that returns `401` during
    upgrade unless `Authorization: Bearer test` is sent.
- `tests/server/server_tls.py` wraps the same routes in an
  `ssl.SSLContext` with a self-signed cert from
  `tests/server/generate_cert.sh`, listens on `https://127.0.0.1:8443`
  and `wss://127.0.0.1:8766`.
- `tests/server/requirements.txt`: `websockets>=12.0`.

## Repository layout

```
aht/
├── alire.toml
├── aht.gpr
├── scripts/
│   ├── fetch_mbedtls.sh
│   └── regen_mbedtls_bindings.sh
├── src/
│   ├── aht.ads
│   ├── aht-bytes.ads
│   ├── aht-url.ads
│   ├── aht-url.adb
│   ├── aht-url-encoding.ads
│   ├── aht-url-encoding.adb
│   ├── aht-transport.ads
│   ├── aht-transport-tcp.ads
│   ├── aht-transport-tcp.adb
│   ├── aht-transport-tls.ads
│   ├── aht-transport-tls.adb
│   ├── aht-mbedtls.ads          -- curated from -fdump-ada-spec
│   ├── aht-mbedtls-*.ads        -- curated per header
│   ├── aht-mbedtls.adb          -- error-code helper
│   ├── aht-http.ads
│   ├── aht-http-methods.ads
│   ├── aht-http-status.ads
│   ├── aht-http-headers.ads
│   ├── aht-http-headers.adb
│   ├── aht-http-request.ads
│   ├── aht-http-request.adb
│   ├── aht-http-response.ads
│   ├── aht-http-response.adb
│   ├── aht-http-io.ads
│   ├── aht-http-io.adb
│   ├── aht-http-client.ads
│   ├── aht-http-client.adb
│   ├── aht-websocket.ads
│   ├── aht-websocket-frames.ads
│   ├── aht-websocket-frames.adb
│   ├── aht-websocket-client.ads
│   └── aht-websocket-client.adb
├── tests/
│   ├── tests.gpr
│   ├── src/
│   │   ├── test_url.adb
│   │   ├── test_url_encoding.adb
│   │   ├── test_headers.adb
│   │   ├── test_http_get.adb
│   │   ├── test_http_chunked.adb
│   │   ├── test_http_post.adb
│   │   ├── test_http_tls.adb
│   │   ├── test_http_auth.adb
│   │   ├── test_ws_echo.adb
│   │   ├── test_ws_fragmentation.adb
│   │   ├── test_ws_close.adb
│   │   ├── test_ws_tls.adb
│   │   └── test_ws_upgrade_headers.adb
│   ├── run_tests.sh
│   └── server/
│       ├── server.py
│       ├── server_tls.py
│       ├── generate_cert.sh
│       └── requirements.txt
└── third_party/           -- populated by fetch_mbedtls.sh; gitignored
```

## Implementation order

1. **Skeleton** — `alire.toml`, `aht.gpr`, empty package specs that `alr build` compiles.
2. **`AHT.Bytes`, `AHT.URL.Encoding`, `AHT.URL`** — pure, trivially unit-testable. Contracts on predicates (`Port_Number`) and `Post` on `Parse`.
3. **`AHT.HTTP.Methods`, `.Status`, `.Headers`** — pure types + case-insensitive multimap with `Type_Invariant`.
4. **`AHT.Transport` + `.TCP`** — `GNAT.Sockets` wrapper.
5. **`AHT.HTTP.IO`** — line reader, chunked decoder on top of a `Transport_Type'Class`.
6. **`AHT.HTTP.Request`, `.Response`, `.Client`** — serialize request, parse response. Test against Python plain HTTP server: `test_http_get`, `test_http_chunked`, `test_http_post`, `test_http_auth`.
7. **mbedTLS fetch + build** (`scripts/fetch_mbedtls.sh`, `alire.toml` pre-build action, link flags).
8. **`AHT.Mbedtls`** bindings — generate via `regen_mbedtls_bindings.sh`, curate into `src/`.
9. **`AHT.Transport.TLS`** — TLS transport. `test_http_tls` green.
10. **`AHT.Websocket.Frames`** — RFC 6455 codec, unit-tested without sockets.
11. **`AHT.Websocket.Client`** — receiver task, `Send_Guard`, `Inbox`, `State`; reuses `AHT.HTTP.*` to drive the upgrade. Tests: `test_ws_echo`, `test_ws_fragmentation`, `test_ws_close`, `test_ws_tls`, `test_ws_upgrade_headers`.

## Critical files

- `src/aht-websocket-client.adb` — WS concurrency core (receiver task + 3 POs).
- `src/aht-http-client.adb` — HTTP request/response flow, scheme dispatch.
- `src/aht-http-headers.adb` — correctness of case-insensitive multimap (invariant-checked).
- `src/aht-websocket-frames.adb` — RFC 6455 framing correctness.
- `src/aht-transport-tls.adb` + `src/aht-mbedtls*.ads` — TLS surface.
- `scripts/fetch_mbedtls.sh`, `scripts/regen_mbedtls_bindings.sh` — dependency reproducibility.
- `alire.toml`, `aht.gpr` — build wiring.

## Verification

End-to-end, runnable by `tests/run_tests.sh`:

1. `python3 -m venv tests/.venv && tests/.venv/bin/pip install -r tests/server/requirements.txt`.
2. `bash tests/server/generate_cert.sh` (once) → `tests/server/cert.pem`, `key.pem`.
3. Start `server.py` (plain HTTP:8764 + WS:8765) and `server_tls.py` (HTTPS:8443 + WSS:8766) in the background.
4. `alr build` (triggers `fetch_mbedtls.sh` on first run; then `regen_mbedtls_bindings.sh` is a manual step when bumping mbedTLS, not per-build).
5. Run each test binary; assert exit 0:
   - **URL / encoding**: `test_url`, `test_url_encoding` — pure-function round trips, edge cases (empty path, IPv6 literals, non-ASCII).
   - **Headers**: `test_headers` — case-insensitive get, multi-value append, invariant holds after 10k random ops.
   - **HTTP plain**: `test_http_get` (`/hello`), `test_http_chunked` (`/chunked` reassembled), `test_http_post` (form-encoded round trip), `test_http_auth` (401 without header, 200 with).
   - **HTTP TLS**: `test_http_tls` (same as above against `https://127.0.0.1:8443` with `CA_Path`).
   - **WS plain**: `test_ws_echo` (1 KiB text + 1 KiB binary echoed), `test_ws_fragmentation` (1 MiB binary split into 64 KiB frames, reassembled, SHA-256 matches), `test_ws_close` (client-initiated + server-initiated close paths both clean).
   - **WS TLS**: `test_ws_tls` — echo over `wss://127.0.0.1:8766`.
   - **WS upgrade headers**: `test_ws_upgrade_headers` — custom `Authorization` header accepted on `/require-auth`, missing header raises `Handshake_Error` with status 401.
6. Stop background servers.

Success criterion: all test binaries exit 0; no tasks left running
(verified by checking environment task's children terminate); Python
servers log clean close frames. Contracts (`pragma Assertion_Policy
(Check)`) active during test builds and do not fire.
