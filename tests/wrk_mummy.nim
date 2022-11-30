import mummy, wrk_shared, os

proc handler(request: Request) =
  case request.uri:
  of "/":
    if request.httpMethod == "GET":
      {.gcsafe.}:
        # sleep(10)
        request.respond(200, body = responseBody)
    else:
      request.respond(405)
  else:
    request.respond(404)

let server = newServer(handler)
server.serve(Port(8080))
