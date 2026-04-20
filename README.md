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

## Documentation

- [`docs/plan.md`](docs/plan.md) — the approved implementation plan.
  Authoritative design spec; update it alongside the code when design
  drifts.
- [`docs/progress.md`](docs/progress.md) — current status: tasks done,
  what's next, which tests pass.
- Subsystem references (one file per subsystem):
  - [`docs/url.md`](docs/url.md) — URL parsing + percent/form encoding.
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
