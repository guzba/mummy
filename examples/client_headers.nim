import mummy, mummy/routers

## This example shows how to access client request headers.

proc indexHandler(request: Request) =
  # Access specific request headers
  echo request.headers["Host"]

  # Access request headers in an iterator
  for (key, value) in request.headers:
    echo key, " = ", value

  # Send all of the request headers back to the client as text
  var headers: HttpHeaders
  headers["Content-Type"] = "text/plain"
  request.respond(200, headers, $request.headers)

var router: Router
router.get("/", indexHandler)

let server = newServer(router)
echo "Serving on http://localhost:8080"
server.serve(Port(8080))
