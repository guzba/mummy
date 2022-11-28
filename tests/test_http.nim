import httpclient, mummy, std/os, zippy

proc handler(request: Request) =
  case request.uri:
  of "/":
    if request.httpMethod == "GET":
      var headers: mummy.HttpHeaders
      headers["Content-Type"] = "text/plain"
      request.respond(200, headers, "Hello, World!")
    else:
      request.respond(405)
  of "/compressed":
    if request.httpMethod == "GET":
      var headers: mummy.HttpHeaders
      headers["Content-Type"] = "text/plain"
      var body: string
      for i in 0 ..< 10:
        body &= "abcdefghijklmnopqrstuvwxyz"
      request.respond(200, headers, body)
    else:
      request.respond(405)
  else:
    request.respond(404)

let server = newServer(handler)

var requesterThread: Thread[void]

proc requesterProc() =
  sleep(1000) # Give the server some time to start up

  block:
    let client = newHttpClient()
    doAssert client.getContent("http://localhost:8081/") == "Hello, World!"

  block:
    let client = newHttpClient()
    doAssert client.post("http://localhost:8081/", "").status == "405"

  block:
    let client = newHttpClient()
    client.headers = newHttpHeaders({"Accept-Encoding": "gzip"})
    let response = client.request("http://localhost:8081/compressed")
    doAssert response.headers["Content-Encoding"] == "gzip"
    discard uncompress(response.body, dfGzip)

  block:
    let client = newHttpClient()
    client.headers = newHttpHeaders({"Accept-Encoding": "deflate"})
    let response = client.request("http://localhost:8081/compressed")
    doAssert response.headers["Content-Encoding"] == "deflate"
    discard uncompress(response.body, dfDeflate)

  echo "Done, shut down the server"
  server.close()

createThread(requesterThread, requesterProc)

# Start the server
server.serve(Port(8081))
