import std/asyncdispatch, std/asynchttpserver

proc main {.async.} =
  var server = newAsyncHttpServer()

  proc cb(req: Request) {.async.} =
    let headers = {"Content-type": "application/json"}
    await req.respond(Http200, "{}", headers.newHttpHeaders())
    # raise newException(ValueError, "bad")

  server.listen(Port(8080))

  while true:
    if server.shouldAcceptRequest():
      await server.acceptRequest(cb)
    else:
      await sleepAsync(500)

waitFor main()
