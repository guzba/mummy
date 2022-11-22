import mummy

proc handler(request: Request) =
  var headers: HttpHeaders
  headers["Content-Type"] = "text/plain"
  request.respond(200, headers, "Hello, World!")

let server = newServer(handler)
server.serve(Port(8080))
