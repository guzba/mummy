import mummy

proc handler(request: Request) =
  case request.uri:
  of "/":
    if request.httpMethod == "GET":
      var headers: HttpHeaders
      headers["Content-Type"] = "text/plain"
      request.respond(200, headers, "Hello, World!")
    else:
      request.respond(405)
  else:
    request.respond(404)

let server = newServer(handler)
echo "Serving on http://localhost:8080"
server.serve(Port(8080))
