import httpserver

proc handler(request: HttpRequest, response: var HttpResponse) =
  # raise newException(ValueError, "bad")
  response.statusCode = 200
  response.headers["Content-Type"] = "application/json"
  response.body = "{}"

let server = newHttpServer(handler)
server.serve(Port(8080))
