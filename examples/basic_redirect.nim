import mummy, mummy/routers

proc firstHandler(request: RoutedRequest) =
  # Responds with a 302 redirect
  request.respond(302, @[("Location", "/second")])

proc secondHandler(request: RoutedRequest) =
  request.respond(200, @[("Content-Type", "text/plain")], "Hello, World!")

var router: Router
router.get("/", firstHandler)
router.get("/second", secondHandler)

let server = newServer(router)
echo "Serving on http://localhost:8080"
server.serve(Port(8080))
