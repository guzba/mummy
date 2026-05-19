when (NimMajor, NimMinor, NimPatch) < (2, 0, 0):
  --threads:on
  --mm:orc

task test, "run tests":
  exec "nim c -r -d:useMalloc tests/test.nim"
  exec "nim c -r -d:useMalloc tests/test_http.nim"
  exec "nim c --mm:atomicArc -r -d:useMalloc tests/test_http.nim"
  exec "nim c -r -d:useMalloc tests/test_http2.nim"
  exec "nim c -r -d:useMalloc tests/test_websockets.nim"
  exec "nim c -r -d:useMalloc -d:mummyNoWorkers tests/fuzz_recv.nim"

