import std/asyncdispatch, std/asynchttpserver, std/strutils, wrk_shared

proc main {.async.} =
  let server = newAsyncHttpServer()

  proc cb(request: Request) {.async.} =
    if request.url.path == "/":
      if request.reqMethod == HttpGet:
        {.gcsafe.}:
          await sleepAsync(10)
          await request.respond(Http200, responseBody)

  server.listen(Port(8080))

  while true:
    if server.shouldAcceptRequest():
      await server.acceptRequest(cb)
    else:
      await sleepAsync(500)

waitFor main()
