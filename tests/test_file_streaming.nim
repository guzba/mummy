import httpclient, mummy, mummy/files, std/os

const
  testPath = "/tmp/mummy-file-streaming-test.txt"
  missingPath = "/tmp/mummy-file-streaming-missing.txt"
  testBody = "abcdefghijklmnopqrstuvwxyz0123456789"

try:
  removeFile(missingPath)
except OSError:
  discard

writeFile(testPath, testBody)

proc handler(request: Request) {.gcsafe.} =
  case request.uri:
  of "/file":
    discard request.respondFile(
      testPath,
      contentType = "text/plain",
      chunkSize = 7
    )
  of "/missing":
    discard request.respondFile(missingPath)
  else:
    request.respond(404)

let server = newServer(handler, streamHandler = fileStreamHandler)

var requesterThread: Thread[void]

proc requesterProc() {.thread, gcsafe.} =
  server.waitUntilReady()

  block:
    let client = newHttpClient()
    let response = client.get("http://localhost:8090/file")
    doAssert response.status in ["200", "200 OK"]
    doAssert response.body == testBody
    doAssert response.headers["Content-Type"] == "text/plain"

  block:
    let client = newHttpClient()
    doAssert client.get("http://localhost:8090/missing").status == "404"

  server.close()

createThread(requesterThread, requesterProc)

server.serve(Port(8090))

try:
  removeFile(testPath)
except OSError:
  discard
