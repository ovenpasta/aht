<!--
SPDX-FileCopyrightText: 2026 Aldo Nicolas Bruno
SPDX-License-Identifier: Apache-2.0
-->

# Logging (`AHT.Log`)

Cross-cutting log facade. The library is silent by default: output
only happens when the application installs a sink.

## Shape

```ada
type Level is (Trace, Debug, Info, Warning, Error);

type Sink_Callback is access procedure
  (Lvl       : Level;
   Subsystem : String;
   Message   : String);

procedure Set_Sink (Cb : Sink_Callback);
procedure Set_Default_Level (Lvl : Level);
procedure Set_Subsystem_Level (Subsystem : String; Lvl : Level);
procedure Clear_Subsystem_Level (Subsystem : String);

function  Is_Enabled (Lvl : Level; Subsystem : String) return Boolean;
procedure Emit       (Lvl : Level; Subsystem : String; Message : String);

procedure Stderr_Sink
  (Lvl : Level; Subsystem : String; Message : String);
function  Synchronized_Sink (Inner : Sink_Callback) return Sink_Callback;
```

## Design

- Silent default. The library never writes to `stdout` or `stderr`
  on its own. The application installs a sink and owns routing
  (stderr, file, syslog, journald).
- Level and subsystem filter. Every call site is tagged with a short
  subsystem string. The library's own sites are `"tcp"`
  (`AHT.Transport.TCP`) and `"http.io"` (`AHT.HTTP.IO`); the tag
  namespace is open and any string works. There is one global
  default minimum level; a per-subsystem override table wins on a
  matching subsystem only. Use it to turn one subsystem up to `Debug`
  without making everything noisy.
- No allocation on the drop path. `Emit` takes a plain `String`;
  formatting is the caller's responsibility. When no sink is
  installed, or the level is below threshold, `Emit` returns after a
  single protected-object read.
- Thread-safe configuration. All mutable state (sink pointer,
  default level, per-subsystem overrides) is behind a protected
  object exposing a single `Snapshot` operation. Readers pull the
  `(sink, threshold)` pair atomically, then invoke the sink outside
  the protected action, so a sink that blocks on I/O does not stall
  other tasks' `Emit` calls.
- Sink thread-safety is the caller's choice. If the installed sink is
  not itself thread-safe, wrap it with `Synchronized_Sink`, which
  returns a module-level trampoline that takes a binary mutex around
  every invocation of the inner sink.

## Generic child `AHT.Log.Tag`

A subsystem instantiates it once per body and uses the shortcuts
directly:

```ada
with AHT.Log.Tag;

package body AHT.Transport.TCP is
   package Log is new AHT.Log.Tag ("tcp");
   ...
   Log.Info ("connected " & Host & ":" & Port'Image);
```

The instance exposes `Trace`, `Debug`, `Info`, `Warning` and `Error`
procedures plus `Enabled (Level) return Boolean`, which is
`AHT.Log.Is_Enabled` with the subsystem baked in.

## Hot-path gating

On cold paths (a TCP connect, one call per request) write
`Log.Debug ("msg " & x)` and let `Emit`'s `Is_Enabled` check drop
the record when disabled; the cost of an unused `&` is negligible
against connect latency.

On hot paths (the chunked-body reader runs one site per chunk;
anything per-byte) wrap the call with `Enabled` so the concatenation
is skipped when the subsystem is muted:

```ada
if Log.Enabled (Debug) then
   Log.Debug ("chunk size=" & Size'Image);
end if;
```

## Ready-made sinks

- `Stderr_Sink` writes `"<LEVEL> [<subsystem>] <message>"` plus a
  newline to `Ada.Text_IO.Standard_Error`. Not thread-safe by itself;
  wrap it with `Synchronized_Sink` if multiple tasks log.
- `Synchronized_Sink (Inner)` returns a thread-safe wrapper around
  `Inner`. The trampoline is a module-level named procedure, so it
  satisfies the library-level accessibility of `Sink_Callback`. Only
  one wrap is active at a time: a second wrap with a different
  non-null `Inner` while the first is live raises `Program_Error`
  rather than repointing the trampoline (which would invalidate every
  `Sink_Callback` value handed out earlier). Pass `null` to release
  the wrap. Re-wrapping with the same `Inner` returns the same
  trampoline.

Covered by `tests/src/test_log.adb`.
