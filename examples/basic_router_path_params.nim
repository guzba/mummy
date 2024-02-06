import mummy, mummy/routers

## http://localhost:8080/objects/abc

proc objectsHandler(request: Request) =
  var headers: HttpHeaders
  headers["Content-Type"] = "text/plain"
  request.respond(200, headers, "Object: " & request.pathParams["id"])

var router: Router
router.get("/objects/@id", objectsHandler)

let server = newServer(router)
echo "Serving on http://localhost:8080"
server.serve(Port(8080))
