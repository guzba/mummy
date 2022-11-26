import mummy, wrk_shared

proc handler(request: Request) =
  case request.uri:
  of "/":
    if request.httpMethod == "GET":
      var headers: HttpHeaders
      headers["Content-Type"] = "text/plain"
      headers["Content-Encoding"] = "identity"
      {.gcsafe.}:
        request.respond(200, headers, responseBody)
    else:
      request.respond(405)
  else:
    request.respond(404)

let server = newServer(handler)
server.serve(Port(8080))
