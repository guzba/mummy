import options, asyncdispatch, httpbeast, wrk_shared

proc onRequest(req: Request): Future[void] =
  if req.httpMethod == some(HttpGet):
    case req.path.get()
    of "/":
      {.gcsafe.}:
        req.send(Http200, responseBody)
    else:
      req.send(Http404)

run(onRequest)
