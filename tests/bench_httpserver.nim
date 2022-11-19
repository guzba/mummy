import httpserver

proc handler(request: HttpRequest): HttpResponse =
  discard

let server = newHttpServer(handler)
server.serve(Port(8080))
