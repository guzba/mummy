import httpclient, mummy, std/atomics

var
  streamStep: Atomic[int]
  closedSeen: Atomic[bool]

proc handler(request: Request) {.gcsafe.} =
  case request.uri:
  of "/stream":
    var headers: mummy.HttpHeaders
    headers["Content-Type"] = "text/plain"
    discard request.respondStream(headers = headers)
  else:
    request.respond(404)

proc streamHandler(stream: ResponseStream, event: StreamEvent) {.gcsafe.} =
  case event:
  of StreamOpen:
    doAssert streamStep.load(moRelaxed) == 0
    streamStep.store(1, moRelaxed)
    doAssert stream.write("hello, ")
    doAssert not stream.write("this write should wait")
  of StreamWritable:
    doAssert streamStep.load(moRelaxed) == 1
    streamStep.store(2, moRelaxed)
    doAssert stream.write("stream")
    stream.close()
  of StreamError:
    doAssert false
  of StreamClosed:
    doAssert streamStep.load(moRelaxed) == 2
    closedSeen.store(true, moRelaxed)

let server = newServer(handler, streamHandler = streamHandler)

var requesterThread: Thread[void]

proc requesterProc() {.thread, gcsafe.} =
  server.waitUntilReady()

  let client = newHttpClient()
  doAssert client.getContent("http://localhost:8089/stream") == "hello, stream"

  server.close()

createThread(requesterThread, requesterProc)

server.serve(Port(8089))

doAssert closedSeen.load(moRelaxed)
