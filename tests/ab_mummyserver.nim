import mummy

var body: string
for i in 0 ..< 1:
  body &= "abcdefghijklmnopqrstuvwxyz"

proc handler(request: Request) =
  case request.uri:
  of "/":
    if request.httpMethod == "GET":
      var headers: HttpHeaders
      headers["Content-Type"] = "text/plain"
      headers["Content-Encoding"] = "identity"
      {.gcsafe.}:
        request.respond(200, headers, body)
    else:
      request.respond(405)
  else:
    request.respond(404)

let server = newServer(handler)
server.serve(Port(8080))
