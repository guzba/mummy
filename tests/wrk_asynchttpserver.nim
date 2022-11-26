import std/asynchttpserver, std/asyncdispatch, std/strutils, wrk_shared

proc main {.async.} =
  let server = newAsyncHttpServer()

  proc cb(request: Request) {.async.} =
    if request.url.path == "/":
      if request.reqMethod == HttpGet:
        let headers = newHttpHeaders()
        headers["Content-Type"] = "text/plain"
        headers["Content-Encoding"] = "identity"
        {.gcsafe.}:
          await request.respond(Http200, responseBody, headers)

  server.listen(Port(8080))

  while true:
    if server.shouldAcceptRequest():
      await server.acceptRequest(cb)
    else:
      await sleepAsync(500)

waitFor main()
