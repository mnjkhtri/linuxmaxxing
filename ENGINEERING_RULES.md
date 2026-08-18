# Engineering Rules

General rules for building and refactoring capture experiments in this repo
(eBPF observers, userspace loaders, shell capture runners, visualizations).
They distill the principles proven in the scheduler observer; they are meant
to apply to memory, IO, virtualization, and future experiments. Treat every
rule as guidance, not a mandate — apply judgment to keep things simple.

## Separation of responsibilities

- Keep one pipeline per concern: kernel observes, userspace serializes,
  the frontend renders. Do not push representation choices into BPF.
- Keep BPF programs about *observation only*: they collect facts, they never
  decide JSON shape, colors, or text labels.
- Keep the binary event ABI, the public schema, and the rendering model as
  three distinct layers, each with its own ownership.
- Put capture lifecycle (attach, poll, read/write) in one place and record
  serialization in another.

## Capture and data model

- Define one canonical binary ABI and one public schema; keep them separate
  and make the mapping explicit.
- Group ABI structs by *semantic facts* (e.g. what happened, where/who,
  resulting state), even when the public JSON groups them differently.
- Emit a single meta/first record carrying static capture facts once, then
  one record per observation. Records stay self-contained and line-oriented.
- Assign sequence numbers in output order so consumers get a stable total
  order without interning undocumented state.
- Prefer compact notations the consumer can read line-by-line (NDJSON, one
  record per line) over nested multi-line blobs when the volume is high.
- Record truncated/partial states explicitly so no consumer mistakes a
  partial observation for a complete one.

## eBPF/kernel vs userspace boundary

- Share the ring-buffer event layout as a single header included by both the
  BPF program and the loader; never paste identical structs into each side.
- Keep that shared ABI header free of JSON vocabulary and representation
  choices: `0/1` not `"red"`, raw `u64` pointers not `"0x..."`, integers not
  booleans. The loader does the conversion.
- Make the shared ABI header compile in both BPF (`-target bpf`) and normal
  userspace builds.
- Treat kernel pointers as opaque identities used to relate objects, never as
  addresses to dereference in userspace.
- Guard every ring-buffer callback against short records to protect the
  byte-for-byte ABI.

## Serialization

- Serialize through a single shared writer that owns JSON syntax only:
  commas, nesting, escaping, and scalar sizing. Never build JSON with ad hoc
  `printf`/comma bookkeeping at each call site.
- Put one canonical normalization boundary: raw capture fields are read only
  there, and everything downstream uses the normalized model.
- Escape untrusted values (task names, strings, keys) in the writer; bound
  fixed-size kernel buffers explicitly.
- Apply project-wide value conventions in one place (e.g. pointer formatting
  and null handling) so consumers see a consistent shape.
- Keep validation/ownership of the public schema in the userspace loader, not
  in BPF.

## Shared utilities

- When two or more projects need the same utility, promote it to a shared
  location; have a single canonical copy, not per-project variants.
- Keep shared utilities generic and dependency-free: they implement one
  mechanism (serialization) and know nothing about any experiment or schema.
- Link shared C utilities into the userspace loader only; never into the BPF
  object or the kernel.

## Build and dependencies

- Express the real dependency graph explicitly: a shared ABI header must be a
  prerequisite of both the BPF object and the loader so a layout change
  rebuilds both sides instead of letting them drift.
- Derive the loader's include path from a shared source directory so one
  header can be included by projects anywhere.
- Pin the loader to the shared serializer source (compile it in) so a bug
  fix is picked up on every build.
- Regenerate `vmlinux.h` from the target kernel's BTF so CO-RE can name the
  exact kernel types it observes.

## Capture orchestration (run scripts)

- Run the real data-producing observer before the workload starts, gate the
  workload on a machine-readable readiness line, and wait for a clean done
  line before declaring success.
- Keep machine data and diagnostics on separate streams: one stream (stdout)
  carries only capture records, the other (stderr) carries both a readiness
  protocol and human diagnostics. Never mix them.
- Use a private tracefs instance per experiment; never mutate the global one
  or leave tracepoints enabled behind.
- Fix the clock deterministically (monotonic) and verify the choice before
  capturing, so timestamps across observers are comparable.
- Tolerate and re-enable/remove every artifact on all exit paths: signals,
  failures, and normal completion must clean up the same way.
- Validate the artifacts after capture with plain, dependency-free tools
  (grep/line checks) before reporting success.
- Keep one workload run driving all cooperating observers so their captures
  correspond to the same interval.

## Frontend parsing and rendering

- Normalize raw capture text in one parse boundary (split by line, parse each
  record, drop malformed lines) and render only from the normalized model.
- Version or cache-bust capture fetches; captures change over time, so never
  cache them forever, and prefer an explicit refresh cue over a stale cached
  copy.
- Keep parsers tolerant: unknown or truncated lines should be counted and
  skipped, not throw the whole view into a failure state.
- Do not hand-parse multi-line/interleaved formats in the view; rely on the
  line-oriented capture format produced by the loader.
- Keep each layout rule in one place: one default plus explicit, reachable
  @media overrides. Remove override chains whose rules are shadowed by a later
  rule at every reachable width, since dead branches mislead later edits.
  (Example: .stage-wrap grid-template-columns was defined four times, and two
  definitions were unreachable.)

## Cleanup and validation

- Every observer and runner must clean up on failure the same way it does on
  success; use traps that also cover signals.
- Fail loudly with a diagnostic on missing prerequisites, wrong privileges,
  or failed validation; never silently write an empty or partial capture.
- Treat empty/invalid captures as errors and surface them, so a later
  analysis does not mistake absence of data for absence of behavior.

## Refactoring discipline

- Preserve behavior while restructuring: when replacing a serializer or ABI
  grouping, verify the new output is equivalent (replay old captures through
  the new code, or regenerate and diff) rather than assuming it.
- Keep declarations and calls on one line when they fit; split only for
  genuinely long argument lists.
- Write comments as complete sentences, one sentence per line, and never cut
  a comment mid-sentence.
- Avoid speculative abstraction: introduce a shared utility or layer only
  when there is a real second consumer or clear need; wrap single fields or
  mirror one-off structures only when it buys something.
- Refactor toward the patterns above incrementally; there is no need to
  rewrite a working experiment. Migrate it when you touch it.