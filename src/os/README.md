<!--
SPDX-FileCopyrightText: 2026 Aldo Nicolas Bruno
SPDX-License-Identifier: Apache-2.0
-->

# Per-OS bodies

One directory per operating system family, holding the units that
cannot be written portably. Exactly one directory compiles, selected
by the `AHT_OS` scenario variable in `aht.gpr`, the same shape as the
`src/tls/{openssl,mbedtls}` split. `src/os` itself is not a source
directory; only its children are.

```
src/aht-random-source.ads          shared spec
src/os/posix/aht-random-source.adb   /dev/urandom
src/os/windows/aht-random-source.adb RtlGenRandom (SystemFunction036)
src/os/posix/aht-dns-link.ads        -lpthread for the resolver shim
src/os/windows/aht-dns-link.ads      -lws2_32 for the resolver shim
```

`AHT.Random.Source` has one body per OS. The counting, the
zero-length case and the fail-closed contract live in the parent
body, so the platforms cannot drift in what they report; a platform
body fills a buffer from the system CSPRNG or raises.

`AHT.DNS.Link` is a body-less spec per OS carrying the part of the
resolver shim's link line that depends on the target:
`csrc/dns/aht_dns.c` uses pthreads on POSIX and `CreateThread` plus
a `CONDITION_VARIABLE` from kernel32 on Windows, where
`getaddrinfo`, `freeaddrinfo`, `inet_ntop` and `WSAStartup` come
from `ws2_32`.

## Scope

Windows is not a supported configuration (`windows = false` in
`alire.toml`). The whole test suite is cross-compiled and run under
wine (see `CONTRIBUTING.md`); nothing has executed on Windows itself.

## Verifying the Windows entropy body from a Linux host

The probe is `scripts/probes/winrand.adb`. It is not in any
`Source_Dirs`, so it never joins the library; it is built by hand with
the recipes below when the Windows body changes. It draws two 16-byte
buffers through `AHT.Random`, and checks that the import binds, that
`RtlGenRandom` reports success, that both buffers were written (they
are pre-filled with a sentinel byte), that the two draws differ, and
that the parent's counters read `draws = 2, bytes = 32`. Every check
sets the exit status.

Two recipes answer two different questions. Run both, and do not read
one's answer as the other's.

- **x86-64, system cross-GNAT**: does the binding behave? This
  toolchain links the UCRT, so the image carries
  `api-ms-win-crt-*.dll` imports that XP does not have; its import
  table says nothing about XP.
- **i686 cross toolchain**: the shipping shape, and the target where
  `Stdcall` diverges from the C convention. This recipe carries the
  import-table assertion.

### x86-64, system cross-GNAT (behaviour only)

```sh
set -e
rm -rf /tmp/winobj64 && mkdir -p /tmp/winobj64
x86_64-w64-mingw32-gnatmake -gnat2022 -D /tmp/winobj64 \
  -I"$PWD/src" -I"$PWD/src/os/windows" \
  "$PWD/scripts/probes/winrand.adb" -o /tmp/winobj64/winrand.exe
WINEDEBUG=-all wine /tmp/winobj64/winrand.exe
```

### i686 cross toolchain (shipping shape, import-table assertion)

```sh
set -e
CROSS_PREFIX=${CROSS_PREFIX:?set to the i686 cross toolchain prefix}
export PATH="$CROSS_PREFIX/usr/bin:$PATH"

rm -rf /tmp/winobj32 && mkdir -p /tmp/winobj32
i686-w64-mingw32.static-gnatmake -gnat2022 -D /tmp/winobj32 \
  -I"$PWD/src" -I"$PWD/src/os/windows" \
  "$PWD/scripts/probes/winrand.adb" -o /tmp/winobj32/winrand.exe

imports=$(i686-w64-mingw32.static-objdump -p /tmp/winobj32/winrand.exe \
          | grep -i "DLL Name")
echo "$imports"

# Positive control first: if objdump produced nothing, every absence
# assertion after it would pass on the empty set.
if ! echo "$imports" | grep -qi "KERNEL32.dll"; then
    echo "winrand: FATAL: no import table read; objdump failed" >&2
    exit 1
fi

# Written as an `if` rather than `! grep -q`: under `set -e` a command
# preceded by `!` is exempt from errexit, so the negated form would
# find bcrypt.dll and let the recipe continue.
if echo "$imports" | grep -qi "bcrypt.dll"; then
    echo "winrand: FATAL: bcrypt.dll imported; not loadable on XP" >&2
    exit 1
fi

WINEDEBUG=-all wine /tmp/winobj32/winrand.exe
```

The probe must be the last command in each recipe so that its exit
status is the script's. Use separate object directories for the two
toolchains: reusing one leaves the 64-bit `aht.o` in place and the
32-bit link fails with `file format not recognized`.

Expected from either recipe: two distinct 16-byte hex draws,
`winrand: OK (draws = 2, bytes = 32)`, and exit 0. The probe exits 1
on any failure, so check the status rather than the text.

### What the recipes establish

- The body compiles and links for both Windows targets.
- `SystemFunction036` binds under `Stdcall` and returns distinct
  16-byte draws under wine on both, with the parent's counters
  reading `draws = 2, bytes = 32`.
- The i686 import table names exactly `ADVAPI32.dll`, `KERNEL32.dll`
  and `msvcrt.dll`: no `bcrypt.dll`, no UCRT.
- The import-table assertion discriminates: against a body calling
  `BCryptGenRandom`, `bcrypt.dll` appears and the check fails.
- The probe discriminates: against a `Get` that writes nothing, the
  sentinel check fails and the probe exits 1. Without the sentinel
  it would compare two patches of stack garbage and pass.

### What they do not establish

- **That this is Microsoft's CSPRNG.** It is wine's `advapi32`. The
  binding, the calling convention and the argument widths are
  exercised; entropy quality is taken on Microsoft's word.
- **That the image runs on Windows XP.** Nothing here has executed
  on XP, and wine implements whatever it is asked for.
- **That the image loads on XP**, beyond the one DLL named above.
  The version boundary runs through `KERNEL32` and `WS2_32` rather
  than between them, so loadability is a question about symbols. Two
  things answer it, neither of them these recipes:
  `_WIN32_WINNT=0x0501` (`Win32_Winnt` in `aht.gpr`), which stops
  the compiler declaring anything newer, and
  `scripts/check_xp_imports.sh`, which reads the built images and is
  run for 32-bit targets by `tests/run_tests.sh`.
- **That the return width is right.** `BOOLEAN` is one byte, arriving
  in `AL` with the upper `EAX` bits undefined. A too-wide declaration
  on `RtlGenRandom` misreads only a failing call, and nothing here
  can make the call fail. The declaration in the body is the only
  defence.

`Stdcall` coincides with the C convention on x86-64, so a
`Convention => C` import would pass the 64-bit recipe and corrupt the
stack on 32-bit Windows; the i686 cross-link is the one that must be
run when this body changes. advapi32 exports the entry point as
`_SystemFunction036@8`, two 4-byte arguments, which is the decoration
`Stdcall` produces and a C import would not.
