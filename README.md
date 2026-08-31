# AHT — Ada HTTP/WebSocket Client

An Ada 2022 library providing a synchronous HTTP/1.1 client and a
concurrent WebSocket (RFC 6455) client on top of a shared transport
layer, with TLS via OpenSSL 3 (default) or mbedTLS.

Every Ada unit lives under the `AHT.*` namespace.

## Features

- **HTTP/1.1 client** — `GET`/`POST`/`PUT`/`DELETE`/`HEAD`/`PATCH`/
  `OPTIONS`, chunked transfer decoding, streaming downloads (push
  callback or straight to an `Ada.Streams` stream), streaming uploads
  (fixed-length or chunked, O(1) memory), async requests with
  cross-task cancellation.
- **WebSocket client** — `ws://` and `wss://`, text + binary,
  fragmentation reassembly, auto ping/pong, clean close handshake,
  blocking `Receive` or push callbacks; exercised against the
  Autobahn|Testsuite conformance harness.
- **TLS** — `https://` and `wss://`, with certificate verification
  against the system trust store, a caller CA bundle (`CA_Path`) or
  anchors embedded in the binary (`CA_PEM`),
  or opt-in `Insecure` mode. Two build-time backends: system
  OpenSSL 3 (default, TLS 1.3) or vendored mbedTLS 3.6
  (`AHT_TLS_BACKEND=mbedtls`) — see [`docs/tls.md`](docs/tls.md).
- **Contracts** — public APIs carry Ada 2012/2022 contracts (subtype
  predicates, `Type_Invariant`, `Pre`/`Post`).

Not (yet) offered: HTTP/2, connection keep-alive (each request runs
`Connection: close`), redirect following, response compression
(`Transfer-Encoding` other than `chunked` is rejected), trailer
surfacing, streaming + async combined.

## Quick start

```ada
with Ada.Text_IO;      use Ada.Text_IO;
with AHT.HTTP.Client;
with AHT.HTTP.Response;

procedure Hello is
   Client : AHT.HTTP.Client.Client_Type;
   Resp   : AHT.HTTP.Response.Response_Type;
begin
   Resp := AHT.HTTP.Client.Get (Client, "https://example.com/");
   Put_Line (Resp.Status'Image);
   Put_Line (Resp.Body_Text);
end Hello;
```

And the WebSocket lifecycle:

```ada
with Ada.Text_IO; use Ada.Text_IO;
with AHT.Bytes;
with AHT.Websocket.Client;

procedure Echo is
   use AHT.Websocket;
   WS  : Client.Client_Type;
   Msg : Client.Message_Type;
begin
   Client.Connect (WS, "wss://echo.example.net/");
   Client.Send_Text (WS, "hello");
   Client.Receive (WS, Msg, Timeout => 5.0);
   Put_Line (AHT.Bytes.To_String (Msg.Payload));
   Client.Close (WS);
end Echo;
```

## Using it from your project

The crate is built with [Alire](https://alire.ada.dev). Until it is in
the community index, pin it by path or git URL from your own crate:

```sh
alr with aht --use=/path/to/aht        # local checkout
alr with aht --use=https://github.com/USER/aht.git
```

## Requirements

- GNAT with Ada 2022 support, via [Alire](https://alire.ada.dev)
  (`alr`).
- POSIX platform (Linux, macOS). Native Windows is not supported yet.
- System OpenSSL 3 development files (`libssl-dev` on Debian/Ubuntu;
  `brew install openssl@3` on macOS with
  `AHT_OPENSSL_DIR=$(brew --prefix openssl@3)`) — the default TLS
  backend links against them.
- Only for the optional mbedTLS backend (`AHT_TLS_BACKEND=mbedtls`):
  network access plus `curl`, `tar`, `make`, and a C compiler on the
  first build — `scripts/fetch_mbedtls.sh` downloads and compiles
  mbedTLS 3.6.7 (checksum-verified) into `third_party/`.
- Integration tests and examples additionally need `python3` (the
  fixture server; its venv installs `websockets`) and `openssl` (test
  certificates).

## Build

```sh
alr build
```

The produced library is `lib/<mode>-<backend>/libaht.a` (default
`debug-openssl`; set `BUILD_MODE=release` for the optimized build —
the TLS backend dimension is described in `docs/tls.md`).

## Run the unit tests

The URL, encoding, and headers tests are pure — no server needed:

```sh
alr exec -- gprbuild -P tests/tests.gpr
./tests/bin/debug-openssl/test_url
./tests/bin/debug-openssl/test_url_encoding
./tests/bin/debug-openssl/test_headers
```

Integration tests (HTTP and WebSocket, plain and TLS) require the
Python test server; the script builds everything, boots the fixtures,
and runs the whole suite:

```sh
bash tests/run_tests.sh
```

## Examples

A ladder of nine self-contained programs under `examples/src/`, ordered
easy → hard, each demonstrating one capability of the client:

1. `ex_01_get` — one-line `Client.Get`; print status + body text.
2. `ex_02_request` — build a `Request_Type`: a POST and a HEAD.
3. `ex_03_streaming` — stream a download two ways: a push `Sink`
   callback, then straight to an `Ada.Streams` stream (a temp file).
4. `ex_04_async_cancel` — `Send_Async` / `Await`, plus cancelling a
   second request against the stall fixture — a test-server route that
   accepts the request and then never responds (`Aborted_Error`).
5. `ex_05_upload` — stream a file body from disk with
   `Sources.Stream_Source` (no hand-rolled `Read_Chunk`).
6. `ex_06_ws_echo` — minimal WebSocket lifecycle: `Connect`, `Send_Text`,
   `Receive`, `Close`.
7. `ex_07_ws_callbacks` — the push API (`Set_On_Message` / `Set_On_Close`
   / `Set_On_Error`), funnelling receiver-task callbacks through a
   protected object.
8. `ex_08_wss_subprotocol` — `wss://` with subprotocol negotiation.
9. `ex_09_https` — the same one-line GET over `https://`, configuring
   the client's `Insecure` / `CA_Path` / `CA_PEM` trust fields.

Each takes an optional URL/host argument and otherwise defaults to the
local Python fixture server from `tests/`. Build them all:

```sh
alr exec -- gprbuild -P examples/examples.gpr
```

Run one (binaries land under `examples/bin/<mode>-<backend>/`,
default `debug-openssl`):

```sh
./examples/bin/debug-openssl/ex_01_get http://127.0.0.1:8764/hello
```

Or build, boot the fixtures, and run the whole ladder in one command:

```sh
bash examples/run_examples.sh
```

## Documentation

One reference file per subsystem:

- [`docs/url.md`](docs/url.md) — URL parsing + percent/form encoding.
- [`docs/bytes_buffer.md`](docs/bytes_buffer.md) — `AHT.Bytes.Buffer`,
  the array-backed byte buffer used for bodies and payloads.
- [`docs/log.md`](docs/log.md) — cross-cutting log facade
  (level × subsystem filter, user-installed sink).
- [`docs/http.md`](docs/http.md) — HTTP methods, status, headers, IO
  helpers, client.
- [`docs/transport.md`](docs/transport.md) — `Transport_Type`
  abstraction, TCP, TLS.
- [`docs/tls.md`](docs/tls.md) — TLS backend selection (OpenSSL /
  mbedTLS), per-backend semantics, the OpenSSL engine design.
- [`docs/mbedtls.md`](docs/mbedtls.md) — how mbedTLS 3.6.7 is
  fetched, built, and bound (the mbedtls backend).
- [`docs/websocket.md`](docs/websocket.md) — frame codec, concurrency
  model, client API.

## Conventions

- **Root namespace** is `AHT`.
- **Contracts**: public APIs use Ada 2012/2022 contracts (subtype
  predicates, `Type_Invariant`, `Pre`/`Post`) wherever they meaningfully
  constrain state. Prefer contracts over explanatory comments.
- **C bindings** (OpenSSL, mbedTLS) are **generated** via
  `gcc -fdump-ada-spec` in a scratch directory and curated into
  `src/` — never hand-written.

## License

Apache 2.0 — see [LICENSE](LICENSE).
