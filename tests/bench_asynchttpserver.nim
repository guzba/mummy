import std/asynchttpserver, std/asyncdispatch

proc main {.async.} =
  var server = newAsyncHttpServer()

  proc cb(req: Request) {.async.} =
    await req.respond(Http200, "OK")

  server.listen(Port(8080))

  while true:
    if server.shouldAcceptRequest():
      await server.acceptRequest(cb)
    else:
      await sleepAsync(500)

waitFor main()
