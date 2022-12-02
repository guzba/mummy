import httpbeast, std/asyncdispatch, std/options, wrk_shared

proc onRequest(req: Request): Future[void] {.async.} =
  if req.httpMethod == some(HttpGet):
    case req.path.get()
    of "/":
      await fdSleep()
      {.gcsafe.}:
        req.send(Http200, responseBody)
    else:
      req.send(Http404)

run(onRequest)
