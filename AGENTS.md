# Repository Guidelines

## Project Identity and Compatibility

- The maintained fork/repository is named **MummyNG**.
- Keep the Nim package, module tree, imports, and public API named `mummy` for now. In particular, preserve `mummy.nimble`, `src/mummy.nim`, `src/mummy/`, and `import mummy` unless a task explicitly requests a package rename.
- Continue using **Mummy** when documenting the library and its API. Use **MummyNG** when distinguishing this maintained fork from upstream.
- Preserve upstream attribution and source compatibility where practical. Avoid unrelated bulk renames.

## Project Structure

- `src/mummy.nim`: HTTP/WebSocket server core, selector loop, worker dispatch, and public server API.
- `src/mummy/`: Supporting public modules such as routers and multipart handling, plus shared internals.
- `tests/`: Standalone unit, integration, protocol, multi-bind, WebSocket, and fuzz-style test programs.
- `examples/`: User-facing examples; update them when public behavior changes.
- `mummy.nimble`: Package metadata, runtime requirements, and optional dependency features.
- `.github/workflows/`: Linux and Windows CI plus documentation publishing.

## Dependencies and Tooling

- Use Atlas for dependency resolution. Do not use Nimble's global package store for normal development.
- Install runtime and test dependencies with:

  ```sh
  atlas install -t:8 --features:testing
  ```

- Atlas manages the local `deps/` directory and the generated Atlas section in `nim.cfg`. Do not hand-edit generated dependency paths; fix the manifest or Atlas configuration instead.
- Keep `deps/` and generated `nim.cfg` out of commits. CI caches `deps/` and regenerates compiler paths with `atlas install`.

## Build and Test Commands

- Compile and run one test with the same baseline flags as CI:

  ```sh
  nim c -r -d:useMalloc tests/test_http.nim
  ```

- The principal CI targets are `tests/test.nim`, `tests/test_http.nim`, `tests/test_http2.nim`, `tests/test_multi_bind.nim`, `tests/test_websockets.nim`, and `tests/fuzz_recv.nim`.
- Run the receive fuzzer harness as CI does:

  ```sh
  nim c -r -d:useMalloc -d:mummyNoWorkers tests/fuzz_recv.nim
  ```

- Mummy requires threads and ARC-family memory management. Test ownership-sensitive changes with `--mm:orc`, and with `--mm:atomicArc` where supported.
- Run focused tests first, followed by the full CI target set when changing `src/mummy.nim`, connection lifecycle, parsing, queues, or shutdown behavior.

## Server-Core Invariants

- Socket I/O and selector registration belong to the selector thread. Request and WebSocket handlers run on worker threads.
- Preserve per-connection identity checks when queueing responses or WebSocket frames; file descriptors and socket handles can be reused.
- Keep cross-thread queues and shared tables behind their designated locks or conditions. Do not invoke user handlers while holding server locks.
- Preserve both the single-address `serve` API and multi-address/multi-port bindings, including IPv4 and IPv6 behavior.
- Shutdown must wake the selector, stop accepting new clients, finish or release queued work safely, close every listening/client socket once, and join worker threads.

## Coding and API Style

- Use 2-space indentation and no tabs.
- Follow Nim conventions: `PascalCase` types, `camelCase` procs and variables, and lowercase or concise `lowerCamel` modules.
- Keep public APIs small and source-compatible. Prefer named arguments in examples when adding optional `newServer` parameters.
- Document exported symbols with Nim doc comments and add tests for new public behavior.
- Avoid broad formatting or refactoring mixed with behavioral fixes.

## Testing Expectations

- Add regression tests for every protocol, lifecycle, or concurrency defect.
- Keep tests deterministic, bound to loopback interfaces, and portable across Linux and Windows.
- Avoid fixed global filesystem paths; use temporary directories/files and clean them up.
- Multi-binding changes should cover distinct ports and IPv4/IPv6 where the runner supports them.
- For concurrency fixes, exercise disconnects, stale queued work, shutdown, and socket-handle reuse—not only the successful request path.

## Commits and Pull Requests

- Use short imperative commit subjects.
- PR descriptions should explain user-visible behavior, compatibility impact, tests run, and any threading, ownership, or shutdown implications.
- Update the README and examples for user-facing changes. Keep fork branding separate from the still-compatible `mummy` package and module names.
