import std/asynchttpserver, std/asyncdispatch, std/strutils

var body: string
for i in 0 ..< 1:
  body &= "abcdefghijklmnopqrstuvwxyz"

proc main {.async.} =
  let server = newAsyncHttpServer()

  proc cb(request: Request) {.async.} =
    if request.url.path == "/":
      if request.reqMethod == HttpGet:
        let headers = newHttpHeaders()
        headers["Content-Type"] = "text/plain"
        headers["Content-Encoding"] = "identity"
        # Get keep-alive working with ab
        if request.headers.hasKey("Connection") and
          cmpIgnoreCase(request.headers["Connection"], "keep-alive") == 0:
          headers["Connection"] = "keep-alive"
        {.gcsafe.}:
          await request.respond(Http200, body, headers)

  server.listen(Port(8080))

  while true:
    if server.shouldAcceptRequest():
      await server.acceptRequest(cb)
    else:
      await sleepAsync(500)

waitFor main()
