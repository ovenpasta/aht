# Logging (`AHT.Log`)

Cross-cutting log facade used by every subsystem. The library is
**silent by default**: output only happens when the application
installs a sink.

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

## Design choices

- **Silent default.** The library never writes to `stdout` or
  `stderr` on its own. The app installs a sink; the app owns
  routing (stderr, file, syslog, journald, …).
- **Level × subsystem filter.** Every call site is tagged with a
  short subsystem string (`"tcp"`, `"tls"`, `"http.io"`,
  `"http.client"`, `"ws.frames"`, `"ws.client"`). There is one
  global default minimum level; a per-subsystem override table
  wins on matching subsystem only. Use this to turn one subsystem
  up to `Debug` without making everything noisy.
- **No allocation on the drop path.** `Emit` takes a plain
  `String`; formatting is the caller's responsibility. When no
  sink is installed, or when the level is below threshold, `Emit`
  returns after a single protected-object read.
- **Thread-safe configuration.** All mutable state (sink pointer,
  default level, per-subsystem overrides) is behind a protected
  object that exposes a single `Snapshot` operation. Readers pull
  the `(sink, threshold)` pair atomically, then invoke the sink
  **outside** the protected action, so a sink that blocks on I/O
  does not stall other tasks' `Emit` calls.
- **Sink thread-safety is the caller's choice.** If the installed
  sink is not itself thread-safe, wrap it with `Synchronized_Sink`;
  that returns a module-level trampoline that takes a binary mutex
  around every invocation of the inner sink.

## Generic child `AHT.Log.Tag`

Every subsystem instantiates once per body and uses the shortcuts
directly:

```ada
with AHT.Log.Tag;

package body AHT.Transport.TCP is
   package Log is new AHT.Log.Tag ("tcp");
   …
   Log.Info ("connected " & Host & ":" & Port'Image);
```

The instance exposes `Trace`, `Debug`, `Info`, `Warning`, `Error`
procedures plus a `Enabled (Level) return Boolean` convenience
matching `AHT.Log.Is_Enabled` with the subsystem baked in.

## Hot-path gating

For **cold paths** — TCP connect, WS close handshake, one call per
request — just write `Log.Debug ("msg " & x)` and let `Emit`'s
cheap `Is_Enabled` check drop the record if disabled. The cost of
an unused `&` is negligible against connect latency.

For **hot paths** — the WS frame decoder (every received frame),
the chunked-body reader (every chunk), anything per-byte — wrap
with `Enabled`:

```ada
if Log.Enabled (Debug) then
   Log.Debug ("frame opcode=" & Opcode'Image
              & " len=" & Length'Image
              & " fin=" & Boolean'Image (Fin));
end if;
```

The guard skips the concatenation cost entirely when the subsystem
is muted. The idiom is ugly; don't pay for it unless the message
actually runs often.

## Ready-made sinks

- `Stderr_Sink` — writes `"<LEVEL> [<subsystem>] <message>"` +
  newline to `Ada.Text_IO.Standard_Error`. Not thread-safe by
  itself; wrap with `Synchronized_Sink` if multiple tasks log.
- `Synchronized_Sink (Inner)` — returns a thread-safe wrapper
  around `Inner`. The trampoline is a module-level named
  procedure, so it satisfies the library-level accessibility of
  `Sink_Callback`. One wrap lives at a time.

## Covered by `tests/bin/test_log`

Five cases:

1. **silent default** — no sink installed ⇒ `Is_Enabled` is false
   for every level and a captured sink that is reset beforehand
   records zero lines after a series of `Emit` / `Tag.Error`
   calls.
2. **capture sink** — records level, subsystem, and message
   verbatim; asserts format `"LEVEL|subsystem|message"`.
3. **default filter** — `Set_Default_Level (Warning)` drops
   `Debug` / `Info` calls and lets `Warning` / `Error` through;
   `Is_Enabled` tracks the threshold.
4. **per-subsystem override** — `Error`-by-default, with `"tcp"`
   overridden to `Debug` (louder than default) and `"ws.frames"`
   overridden to `Error` (at default). Asserts three messages
   survive out of five; then `Clear_Subsystem_Level ("tcp")`
   drops the override.
5. **concurrent `Synchronized_Sink`** — four tasks × 200
   iterations each call `Emit` through a deliberately racy inner
   sink (reads a global counter, sleeps 1 ms, writes back).
   Unserialized it loses hundreds of bumps; with
   `Synchronized_Sink` the counter ends at exactly 800.
