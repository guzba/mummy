import mummy, mummy/routers

## This example shows how to return a custom response for requests
## that do not have a matching route (return a 404).
## The same idea can be used for `methodNotAllowedHandler` (405) and
## `errorHandler` (500) responses.

proc custom404(request: Request) =
  ## This is a custom 404 handler
  const body = "<h1>I'm not here</h1>"

  var headers: HttpHeaders
  headers["Content-Type"] = "text/html"

  if request.httpMethod == "HEAD":
    headers["Content-Length"] = $body.len
    request.respond(404, headers)
  else:
    request.respond(404, headers, body)

proc indexHandler(request: Request) =
  var headers: HttpHeaders
  headers["Content-Type"] = "text/plain"
  request.respond(200, headers, "Hello, World!")

var router: Router

# Custom 404 handler
router.notFoundHandler = custom404

# Normal routes
router.get("/", indexHandler)

let server = newServer(router)
echo "Serving on http://localhost:8080"
server.serve(Port(8080))
