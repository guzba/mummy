import mummy, mummy/routers

## This example shows how to create custom handlers that take more parameters
## than just the Request object.
##
## To demonstrate, we define an AuthenticatedHandler type which represents
## a handler that is called with both the Request object and the userId
## of the authenticated user making the request.
##
## We can then create any number of handlers using the AuthenticatedHandler
## signature and have them all go through one authentication code path.

type AuthenticatedHandler = proc(request: RoutedRequest, userId: string) {.gcsafe.}

proc indexHandler(request: RoutedRequest) =
  request.respond(200, @[("Content-Type", "text/plain")], "Hello, World!")

proc profileHandler(request: RoutedRequest, userId: string) =
  # This is the authenticated endpoint for a user's profile.
  request.respond(200, @[("Content-Type", "text/plain")], "Hello " & userId)

proc settingsHandler(request: RoutedRequest, userId: string) =
  # This is the authenticated endpoint for a user's settings.
  request.respond(200, @[("Content-Type", "text/plain")], "Settings for " & userId)

proc toHandler(wrapped: AuthenticatedHandler): RouteHandler =
  # Calling `toHandler` returns a simple RouteHandler proc for an
  # AuthenticatedHandler so it can be registered with a Router.
  return proc(request: RoutedRequest) =
    # This code runs before we call the AuthenticatedHandler.
    # We can do the user authentication that all AuthenticatedHandlers
    # expect here.
    # (The auth faked in this example)
    let accessToken = request.headers["Access-Token"]
    if accessToken == "abc":
      # This is a valid token so call the wrapped AuthenticatedHandler.
      wrapped(request, "User 123")
    else:
      # This is not a valid access token, send error response.
      request.respond(401, @[("Content-Type", "text/plain")], "Invalid token")

var router: Router
router.get("/", indexHandler)
router.get("/me", profileHandler.toHandler())
router.get("/me/settings", settingsHandler.toHandler())

let server = newServer(router)
echo "Serving on http://localhost:8080"
server.serve(Port(8080))

## While only one parameter of a simple string type is added in this example,
## there are no limitations with this approach.
##
## You can add any number of parameters of any type you want to a custom
## handler type and then use the example above for how to wrap it in a
## simple RouteHandler.
