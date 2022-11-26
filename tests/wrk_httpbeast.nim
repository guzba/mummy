import options, asyncdispatch, httpbeast, wrk_shared

proc onRequest(req: Request): Future[void] =
  if req.httpMethod == some(HttpGet):
    case req.path.get()
    of "/":
      let headers = "Content-Type: text/plain\r\nContent-Encoding: identity"
      {.gcsafe.}:
        req.send(Http200, responseBody, headers)
    else:
      req.send(Http404)

run(onRequest)
