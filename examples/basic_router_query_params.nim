import mummy, mummy/routers

## http://localhost:8080/search?name=foo

proc searchHandler(request: Request) =
  var headers: HttpHeaders
  headers["Content-Type"] = "text/plain"
  request.respond(200, headers, "Name: " & request.queryParams["name"])

var router: Router
router.get("/search", searchHandler)

let server = newServer(router)
echo "Serving on http://localhost:8080"
server.serve(Port(8080))
