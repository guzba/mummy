import httpserver

proc handler*(request: HttpRequest) =
  discard

let server = newHttpServer(handler)
server.serve(Port(8080))
