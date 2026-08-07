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

The probe is `src/os/winrand.adb`, committed alongside this file so
the recipe is actually reproducible. It is not in any `Source_Dirs`
— `src/os` itself is not a source directory, only its per-OS
children — so it never joins the library.

From the repository root:

```sh
mkdir -p /tmp/winobj
x86_64-w64-mingw32-gnatmake -gnat2022 -D /tmp/winobj \
  -I"$PWD/src" -I"$PWD/src/os/windows" \
  "$PWD/src/os/winrand.adb" -o /tmp/winobj/winrand.exe
x86_64-w64-mingw32-objdump -p /tmp/winobj/winrand.exe | grep -i bcrypt
WINEDEBUG=-all wine /tmp/winobj/winrand.exe
```

Expected output: two distinct 16-byte hex draws, `distinct = TRUE`,
`draws = 2  bytes = 32`, `OK`.

For 32-bit — the target where the `Stdcall` convention actually
differs from C — substitute `i686-w64-mingw32-` for the tool prefix.

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
64-bit test above and corrupt the stack on 32-bit Windows — which is
why the 32-bit cross-link is worth running when this body changes.
That has been done: the body compiles and links for `i686-w64-mingw32`
and the PE imports `bcrypt.dll!BCryptGenRandom` there too.
