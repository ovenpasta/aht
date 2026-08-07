# Per-OS bodies

One directory per operating system family, holding the bodies of units
that cannot be written portably. Exactly one directory compiles,
selected by the `AHT_OS` scenario variable in `aht.gpr` — the same
shape as the `src/tls/{openssl,mbedtls}` split.

```
src/aht-random-source.ads     shared spec
src/os/posix/…-source.adb     /dev/urandom
src/os/windows/…-source.adb   BCryptGenRandom
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

```sh
mkdir -p /tmp/winobj && cd /tmp/winobj
x86_64-w64-mingw32-gnatmake -gnat2022 \
  -I<repo>/src -I<repo>/src/os/windows \
  winrand.adb -o winrand.exe          # a main that calls AHT.Random.Fill twice
x86_64-w64-mingw32-objdump -p winrand.exe | grep -i bcrypt
WINEDEBUG=-all wine winrand.exe
```

What that established, on 2026-08-07 with GNAT 15.2.0 for
`x86_64-w64-mingw32`:

- the body compiles clean for the Windows target;
- it links, so `pragma Linker_Options ("-lbcrypt")` resolves and the
  `Stdcall` import binds;
- `bcrypt.dll` / `BCryptGenRandom` appear in the PE import table, so
  the call is really going to the OS;
- under wine it returns distinct 16-byte draws and the shared counters
  read `draws = 2, bytes = 32`.

What it did **not** establish: this was wine's `bcrypt`, not
Microsoft's. The binding, the calling convention, the flag and the
`NTSTATUS` check are all exercised; the actual entropy quality of a
real Windows CSPRNG is taken on Microsoft's word, as it would be
anyway.

`Stdcall` is deliberate rather than incidental. It coincides with the
C convention on x86-64, so a `Convention => C` import would pass the
test above and corrupt the stack on 32-bit Windows.
