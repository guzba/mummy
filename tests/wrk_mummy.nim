import mummy, wrk_shared

proc handler(request: Request) =
  case request.uri:
  of "/":
    if request.httpMethod == "GET":
      {.gcsafe.}:
        request.respond(200, body = responseBody)
    else:
      request.respond(405)
  else:
    request.respond(404)

let server = newServer(handler)
server.serve(Port(8080))
