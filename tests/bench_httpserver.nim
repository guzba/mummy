import httpserver

proc handler(request: HttpRequest, response: var HttpResponse) =
  response.statusCode = 200
  response.body = "OK"

let server = newHttpServer(handler)
server.serve(Port(8080))
