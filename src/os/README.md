# Per-OS bodies

One directory per operating system family, holding the bodies of units
that cannot be written portably. Exactly one directory compiles,
selected by the `AHT_OS` scenario variable in `aht.gpr` — the same
shape as the `src/tls/{openssl,mbedtls}` split.

```
src/aht-random-source.ads     shared spec
src/os/posix/…-source.adb     /dev/urandom
src/os/windows/…-source.adb   RtlGenRandom
```

Today that is one unit, `AHT.Random.Source`. The counting, the
zero-length case and the fail-closed contract live in the parent body
so the platforms cannot drift in what they report; a platform body has
one job, which is to fill a buffer from the system CSPRNG or raise.

## Scope of the Windows work

**`AHT.Random` builds and runs on Windows. The rest of the library has
not been verified there.** The transports, the TLS backends and the
test harness are POSIX-tested only, so this removes one blocker rather
than delivering Windows support, and `alire.toml` still says
POSIX-only on purpose.

## Verifying the Windows body from a Linux host

It was cross-compiled, cross-linked and executed before being
committed, not merely written:

The probe is `src/os/winrand.adb`, committed alongside this file so
the recipe is actually reproducible. It is not in any `Source_Dirs`
— `src/os` itself is not a source directory, only its per-OS
children — so it never joins the library.

**Two recipes answering two different questions.** Run both, and do
not read either one's answer as the other's:

- **x86-64, system cross-GNAT** — does the binding behave? Its import
  table is *not* evidence about Windows XP. This toolchain links the
  UCRT, so the image carries thirteen `api-ms-win-crt-*.dll` imports
  that XP never had and cannot be given. It is the fast loop, not the
  shipping shape.
- **i686 via CROSS_PREFIX** — the toolchain that actually ships, and the target
  where `Stdcall` diverges from C. This one carries the XP
  import-table assertion.

### x86-64, system cross-GNAT — behaviour only

```sh
set -e
rm -rf /tmp/winobj64 && mkdir -p /tmp/winobj64
x86_64-w64-mingw32-gnatmake -gnat2022 -D /tmp/winobj64 \
  -I"$PWD/src" -I"$PWD/src/os/windows" \
  "$PWD/src/os/winrand.adb" -o /tmp/winobj64/winrand.exe
WINEDEBUG=-all wine /tmp/winobj64/winrand.exe
```

### i686 via CROSS_PREFIX — shipping toolchain, and the XP assertion

```sh
set -e
CROSS_PREFIX=${CROSS_PREFIX:-$HOME/cross-i686}
export PATH="$CROSS_PREFIX/usr/bin:$PATH"

rm -rf /tmp/winobj32 && mkdir -p /tmp/winobj32
i686-w64-mingw32.static-gnatmake -gnat2022 -D /tmp/winobj32 \
  -I"$PWD/src" -I"$PWD/src/os/windows" \
  "$PWD/src/os/winrand.adb" -o /tmp/winobj32/winrand.exe

imports=$(i686-w64-mingw32.static-objdump -p /tmp/winobj32/winrand.exe \
          | grep -i "DLL Name")
echo "$imports"

# Positive control, and it goes first: if objdump produced nothing at
# all, every absence assertion after it would pass on the empty set.
if ! echo "$imports" | grep -qi "KERNEL32.dll"; then
    echo "winrand: FATAL — no import table read; objdump failed" >&2
    exit 1
fi

# The assertion. Written as an `if`, deliberately, and not as
# `! echo "$imports" | grep -qi bcrypt`: under `set -e` a command
# preceded by `!` is exempt from errexit, so the negated form would
# find bcrypt.dll, print nothing, and let the recipe continue green.
if echo "$imports" | grep -qi "bcrypt.dll"; then
    echo "winrand: FATAL — bcrypt.dll imported; not loadable on XP" >&2
    exit 1
fi

WINEDEBUG=-all wine /tmp/winobj32/winrand.exe
```

**Separate object directories, not one reused.** Substituting only
the tool prefix and keeping `/tmp/winobj` leaves the 64-bit `aht.o`
in place and the 32-bit link fails with
`file format not recognized`.

Expected from either: two distinct 16-byte hex draws,
`winrand: OK (draws = 2, bytes = 32)`, and **exit 0**. The probe
asserts all of that and exits 1 on any failure, so check the status
rather than reading the text.

Note the `set -e` and the absence of a trailing `echo "exit=$?"`.
That echo was there to *show* the status and destroyed it: it
succeeds, so it becomes the script's last command and a failing probe
still exits 0 — the recipe reported the very property it was breaking.
The probe must be the final command, or its status must be propagated
explicitly. The `!`-exemption note above is that same trap in
different clothes, which is why the assertions are spelled out long.

What this established, on 2026-08-27, with CROSS_PREFIX
`i686-w64-mingw32.static` and the system `x86_64-w64-mingw32` GNAT:

- the body compiles clean and links for both Windows targets;
- `SystemFunction036` binds under `Stdcall` and returns distinct
  16-byte draws under wine on both, with the shared counters reading
  `draws = 2, bytes = 32` and exit 0;
- the i686 import table is exactly `ADVAPI32.dll`, `KERNEL32.dll` and
  `msvcrt.dll` — no `bcrypt.dll`, no UCRT — which is an XP-loadable
  shape;
- the assertion discriminates rather than merely passing: rebuilt
  against a body calling `BCryptGenRandom`, `bcrypt.dll` appears in
  that table and the check fails;
- the probe discriminates too: against a `Get` that writes nothing,
  it fails on the sentinel check and exits 1. Without the sentinel it
  reports `OK (draws = 2, bytes = 32)` and exits 0 against that same
  body, because it compares two patches of stack garbage. See the note
  in `winrand.adb`.

What it did **not** establish:

- **That this is Microsoft's CSPRNG.** It was wine's `advapi32`. The
  binding, the calling convention and the argument widths are
  exercised; entropy quality is taken on Microsoft's word, as it would
  be anyway.
- **That the image runs on Windows XP.** The import table says it can
  *load*. Nothing here has executed on XP, and wine cannot stand in
  for that — wine implements whatever DLL it is asked for, so a body
  importing a Vista-only DLL passes this recipe while being unloadable
  on the target. The two checks have disjoint blind spots and neither
  is redundant.
- **That the return width is right.** A too-wide declaration on
  `RtlGenRandom` misreads only a *failing* call, and nothing here can
  make it fail. The declaration in the body is the only defence, and
  it carries the argument.

`Stdcall` is deliberate rather than incidental. It coincides with the
C convention on x86-64, so a `Convention => C` import would pass the
64-bit recipe and corrupt the stack on 32-bit Windows — which is why
the i686 cross-link is the one that must be run when this body
changes. advapi32 exports the entry point as `_SystemFunction036@8`:
two 4-byte arguments, the decoration `Stdcall` produces and a C import
would not.
