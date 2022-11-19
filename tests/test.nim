import httpserver, std/os, puppy

const responseBody = "Hello, World!"

var serverThread: Thread[void]

proc serverProc() =
  proc handler(request: HttpRequest, response: var HttpResponse) =
    response.statusCode = 200
    response.body = responseBody

  let server = newHttpServer(handler)
  server.serve(Port(8080))

createThread(serverThread, serverProc)

sleep(1000)

let
  request = newRequest("http://localhost:8080")
  response = fetch(request)

doAssert response.code == 200
doAssert response.body == responseBody
