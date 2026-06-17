# AHT — Ada HTTP/WebSocket Client

An Ada 2022 library providing a synchronous HTTP/1.1 client and a
concurrent WebSocket (RFC 6455) client on top of a shared transport
layer, with TLS via mbedTLS v2.28.9.

Every Ada unit lives under the `AHT.*` namespace.

## Build

```sh
alr build
```

On the first build this triggers `scripts/fetch_mbedtls.sh` to fetch and
compile mbedTLS v2.28.9 locally into `third_party/`. The produced
library is `lib/libaht.a`.

## Run the unit tests

The URL, encoding, and headers tests are pure — no server needed:

```sh
alr exec -- gprbuild -P tests/tests.gpr
./tests/bin/test_url
./tests/bin/test_url_encoding
./tests/bin/test_headers
```

Integration tests (HTTP and WebSocket, plain and TLS) require the
Python test server:

```sh
bash tests/run_tests.sh
```

## Examples

A ladder of eight self-contained programs under `examples/src/`, ordered
easy → hard, each demonstrating one capability of the client:

1. `ex_01_get` — one-line `Client.Get`; print status + body text.
2. `ex_02_request` — build a `Request_Type`: a POST and a HEAD.
3. `ex_03_streaming` — stream a download two ways: a push `Sink`
   callback, then straight to an `Ada.Streams` stream (a temp file).
4. `ex_04_async_cancel` — `Send_Async` / `Await`, plus cancelling a
   second request against the stall fixture (`Aborted_Error`).
5. `ex_05_upload` — stream a file body from disk with
   `Sources.Stream_Source` (no hand-rolled `Read_Chunk`).
6. `ex_06_ws_echo` — minimal WebSocket lifecycle: `Connect`, `Send_Text`,
   `Receive`, `Close`.
7. `ex_07_ws_callbacks` — the push API (`Set_On_Message` / `Set_On_Close`
   / `Set_On_Error`), funnelling receiver-task callbacks through a
   protected object.
8. `ex_08_wss_subprotocol` — `wss://` with subprotocol negotiation.

Each takes an optional URL/host argument and otherwise defaults to the
bundled Python fixtures. Build them all:

```sh
alr exec -- gprbuild -P examples/examples.gpr
```

Run one (binaries land under `examples/bin/<mode>/`, default `debug`):

```sh
./examples/bin/debug/ex_01_get http://127.0.0.1:8764/hello
```

Or build, boot the fixtures, and run the whole ladder in one command:

```sh
bash examples/run_examples.sh
```

## Documentation

- [`docs/plan.md`](docs/plan.md) — the approved implementation plan.
  Authoritative design spec; update it alongside the code when design
  drifts.
- [`docs/progress.md`](docs/progress.md) — current status: tasks done,
  what's next, which tests pass.
- Subsystem references (one file per subsystem):
  - [`docs/url.md`](docs/url.md) — URL parsing + percent/form encoding.
  - [`docs/log.md`](docs/log.md) — cross-cutting log facade
    (level × subsystem filter, user-installed sink).
  - [`docs/http.md`](docs/http.md) — HTTP methods, status, headers, IO
    helpers, client.
  - [`docs/transport.md`](docs/transport.md) — `Transport_Type`
    abstraction, TCP, TLS.
  - [`docs/mbedtls.md`](docs/mbedtls.md) — how mbedTLS v2.28.9 is
    fetched, built, and bound.
  - [`docs/websocket.md`](docs/websocket.md) — frame codec, concurrency
    model, client API.

## Conventions

- **Root namespace** is `AHT`.
- **Contracts**: public APIs use Ada 2012/2022 contracts (subtype
  predicates, `Type_Invariant`, `Pre`/`Post`) wherever they meaningfully
  constrain state. Prefer contracts over explanatory comments.
- **C bindings** (currently mbedTLS) are **generated** via
  `gcc -fdump-ada-spec` in a scratch directory and curated into
  `src/` — never hand-written.

## License

Apache 2.0.
