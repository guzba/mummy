import mummy, httpclient, std/os

proc handler(request: Request) =
  var headers: mummy.HttpHeaders
  headers["Content-Type"] = "text/plain"
  request.respond(200, headers, "Hello, World!")

let server = newServer(handler)

var requesterThread: Thread[void]

proc requesterProc() =
  sleep(1000) # Give the server some time to start up

  block:
    let client = newHttpClient()
    doAssert client.getContent("http://localhost:8081/") == "Hello, World!"
    server.close()

createThread(requesterThread, requesterProc)

# Start the server
server.serve(Port(8081))
