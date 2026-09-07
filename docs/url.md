<!--
SPDX-FileCopyrightText: 2026 Aldo Nicolas Bruno
SPDX-License-Identifier: Apache-2.0
-->

# URL & URL Encoding

Packages: `AHT.URL`, `AHT.URL.Encoding`.

## `AHT.URL`

Parses and rebuilds `http://`, `https://`, `ws://`, and `wss://` URLs.

### Types

- `subtype Port_Number is Positive range 1 .. 65_535;`
- `type Scheme_Kind is (HTTP, HTTPS, WS, WSS);`
- `type URL_Type` — record with:
  - `Scheme : Scheme_Kind`
  - `User_Info : Unbounded_String` — whatever sat between `scheme://`
    and `@`, if any. Parsed so it cannot corrupt `Host`.
    **Not** auto-translated into an `Authorization` header.
  - `Host : Unbounded_String` — IPv6 literals are stored **without**
    the surrounding brackets (`[::1]` → `::1`).
  - `Is_IPv6 : Boolean`
  - `Port : Port_Number` — defaults to the scheme's standard port if
    the URL omitted one.
  - `Path`, `Query`, `Fragment : Unbounded_String`.

### Operations

- `Default_Port (S) return Port_Number` — 80/443/80/443.
- `Is_Secure (S) return Boolean` — true for `HTTPS`/`WSS`.
- `Parse (Input) return URL_Type`
  - **Post**: `Length (Host) > 0`.
  - Raises `Parse_Error` on malformed input (missing scheme, empty
    host, non-numeric port, unterminated IPv6 literal, …).
- `To_String (U) return String` — round-trips a parsed URL; omits the
  port when it equals `Default_Port (Scheme)`.
- `Host_Literal (U) return String` — host as it appears in a URL
  (`"[::1]"` for IPv6, plain string otherwise).
- `Request_Target (U) return String` — `"path?query"` for the HTTP
  request line.

### Notes

- Authority split: first looks for the last `@` (userinfo), then for
  `[...]` (IPv6). Only if the host is not bracketed does it split on
  the last `:` for port.
- Scheme comparison is case-insensitive.
- `Parse` rejects unsupported schemes; it does not silently downgrade.

## `AHT.URL.Encoding`

RFC 3986 §2.3 percent encoding and `application/x-www-form-urlencoded`
encoding.

### Byte-oriented contract

All four functions treat their `String` argument as a sequence of
bytes (`Character'Pos` = byte value). For non-ASCII text the caller
is responsible for UTF-8 encoding first. This is intentional:

- `Percent_Encode` / `Form_Encode` only leave **ASCII** unreserved
  characters untouched (`A-Z` `a-z` `0-9` `-` `.` `_` `~`); every
  other byte, including any Latin-1 character ≥ 0x80, is emitted
  as `%HH` (uppercase hex).
- The Ada standard function `Ada.Characters.Handling.Is_Alphanumeric`
  is **not** used here — it would classify accented Latin-1 letters
  as unreserved and produce non-portable URLs.

### Operations

- `Percent_Encode (S) return String`
- `Percent_Decode (S) return String` — raises `Constraint_Error` on
  malformed `%XX` sequences.
- `Form_Encode (S) return String` — space becomes `+`; everything
  else follows percent encoding.
- `Form_Decode (S) return String` — `+` becomes space first; then
  percent-decoded.

## Tests

`tests/src/test_url.adb`, `tests/src/test_url_encoding.adb`. Both run
without external dependencies.
