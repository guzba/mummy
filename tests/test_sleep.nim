import std/os, mummy, std/atomics, std/httpclient

var
  requestCounter: Atomic[int]
  doneCounter: Atomic[int]

proc handler(request: Request) =
  discard requestCounter.fetchAdd(1, moRelaxed)
  request.respond(200)
  sleep(10_000)
  discard doneCounter.fetchAdd(1, moRelaxed)

let server = newServer(handler, workerThreads = 10)

var serverThread: Thread[void]

proc serverProc() =
  {.gcsafe.}:
    server.serve(Port(8080))

createThread(serverThread, serverProc)

server.waitUntilReady()

for i in 0 ..< 10:
  block:
    let client = newHttpClient()
    discard client.getContent("http://localhost:8080/")

doAssert requestCounter.exchange(0, moRelaxed) == 10
doAssert doneCounter.exchange(0, moRelaxed) == 0

echo "Done, shut down the server"
server.close()
