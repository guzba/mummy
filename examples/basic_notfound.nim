##
## How to handle not found requests. Same concept can be used for
## `methodNotAllowedHandler` and `errorHandler` (found in `mummy/routers`).
##

import mummy, mummy/routers

proc customNotFound(request: Request) =
  ## This is a custom 404 handler
  const body = "<h1>I'm not here</h1>"

  var headers: httpheaders.HttpHeaders
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

# Custom not found handler
router.notFoundHandler = customNotFound

# Normal routes
router.get("/", indexHandler)

let server = newServer(router)
echo "Serving on http://localhost:8080"
server.serve(Port(8080))
