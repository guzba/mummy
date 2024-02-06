import ../mummy, std/strutils, webby/urls

export queryparams

type
  Router* = object
    ## Routes HTTP requests. See `addRoute` for more info.
    notFoundHandler*: RequestHandler
      ## Called when no routes match the request URI
    methodNotAllowedHandler*: RequestHandler
      ## Called when the HTTP method is not registered for the route
    errorHandler*: RequestErrorHandler
      ## Called when the route request handler raises an Exception
    routes*: seq[Route]

  RequestErrorHandler* = proc(request: Request, e: ref Exception) {.gcsafe.}

  Route = object
    httpMethod: string
    parts: seq[string]
    handler: RequestHandler

proc addRoute*(
  router: var Router,
  httpMethod, route: string | static string,
  handler: RequestHandler
) =
  ## Adds a route to the router. Routes are a path string and an HTTP method.
  ## When a request comes in, it is tested against the routes in the order
  ## they were added. The handler for the first matching route is called.
  ## The route path can have `*` and `**` wildcards.
  ## The `*` wildcard represents 0 or more characters, excluding `/`.
  ## Valid uses are:
  ##   "/*"              (wildcard path segment)
  ##   "/*.json"         (wildcard prefix)
  ##   "/page_*"         (wildcard suffix)
  ##   "/*_something_*"  (wildcard prefix and suffix)
  ## The `**` wildcard represents 1 or more path segments delimited by `/`.
  ## Valid uses are:
  ##   "/**"             (wildcard path)
  ##   "/**/thing"       (wildcard path with suffix)
  ##   "/thing/**         (wildcard path with prefix)
  ## See tests/test_routers.nim for more complex routing examples.

  when route is static string:
    when route == "":
      {.error: "Invalid empty route".}
    when route[0] != '/':
      {.error: "Routes must begin with /".}
  else:
    if route == "":
      raise newException(MummyError, "Invalid empty route")
    elif route[0] != '/':
      raise newException(MummyError, "Routes must begin with /")

  var parts = route.split('/')
  parts.delete(0)

  var i: int
  while i < parts.len - 1:
    if parts[i] == "**":
      var j = i + 1
      if (
        parts[j] == "*" or
        parts[j] == "**" or
        (parts[j].len >= 2 and parts[j].startsWith('@'))
      ):
        raise newException(
          MummyError,
          "Route ** followed by another *, ** or named param is not supported"
        )
    inc i

  router.routes.add(Route(
    httpMethod: httpMethod,
    parts: move parts,
    handler: handler
  ))

proc get*(
  router: var Router,
  route: string | static string,
  handler: RequestHandler
) =
  ## Adds a route for GET requests. See `addRoute` for more info.
  router.addRoute("GET", route, handler)

proc head*(
  router: var Router,
  route: string | static string,
  handler: RequestHandler
) =
  ## Adds a route for HEAD requests. See `addRoute` for more info.
  router.addRoute("HEAD", route, handler)

proc post*(
  router: var Router,
  route: string | static string,
  handler: RequestHandler
) =
  ## Adds a route for POST requests. See `addRoute` for more info.
  router.addRoute("POST", route, handler)

proc put*(
  router: var Router,
  route: string | static string,
  handler: RequestHandler
) =
  ## Adds a route for PUT requests. See `addRoute` for more info.
  router.addRoute("PUT", route, handler)

proc delete*(
  router: var Router,
  route: string | static string,
  handler: RequestHandler
) =
  ## Adds a route for DELETE requests. See `addRoute` for more info.
  router.addRoute("DELETE", route, handler)

proc options*(
  router: var Router,
  route: string | static string,
  handler: RequestHandler
) =
  ## Adds a route for OPTIONS requests. See `addRoute` for more info.
  router.addRoute("OPTIONS", route, handler)

proc patch*(
  router: var Router,
  route: string | static string,
  handler: RequestHandler
) =
  ## Adds a route for PATCH requests. See `addRoute` for more info.
  router.addRoute("PATCH", route, handler)

proc defaultNotFoundHandler(request: Request) =
  const body = "<h1>Not Found</h1>"

  var headers: HttpHeaders
  headers["Content-Type"] = "text/html"

  if request.httpMethod == "HEAD":
    headers["Content-Length"] = $body.len
    request.respond(404, headers)
  else:
    request.respond(404, headers, body)

proc defaultMethodNotAllowedHandler(request: Request) =
  const body = "<h1>Method Not Allowed</h1>"

  var headers: HttpHeaders
  headers["Content-Type"] = "text/html"

  if request.httpMethod == "HEAD":
    headers["Content-Length"] = $body.len
    request.respond(405, headers)
  else:
    request.respond(405, headers, body)

proc isPartialWildcard(test: string): bool {.inline.} =
  test.len >= 2 and test.startsWith('*') or test.endsWith('*')

proc partialWildcardMatches(partialWildcard, test: string): bool {.inline.} =
  let
    wildcardPrefix = partialWildcard[0] == '*'
    wildcardSuffix = partialWildcard[^1] == '*'

  var
    literalLen = partialWildcard.len
    literalStart = 0
  if wildcardPrefix:
    dec literalLen
    inc literalStart
  if wildcardSuffix:
    dec literalLen

  if literalLen > test.len:
    return false

  if wildcardPrefix and not wildcardSuffix:
    return equalMem(
      partialWildcard[1].unsafeAddr,
      test[test.len - literalLen].unsafeAddr,
      literalLen
    )

  if wildcardSuffix and not wildcardPrefix:
    return equalMem(
      partialWildcard[0].unsafeAddr,
      test[0].unsafeAddr,
      literalLen
    )

  # Wildcard prefix and suffix *<something>*

  let literal = partialWildcard[1 .. ^2]
  return literal in test

proc toHandler*(router: Router): RequestHandler =
  return proc(request: Request) =
    ## All requests arrive here to be routed

    template notFound() =
      if router.notFoundHandler != nil:
        router.notFoundHandler(request)
      else:
        defaultNotFoundHandler(request)

    if request.path.len == 0 or request.path[0] != '/':
      notFound()
      return

    try:
      let pathParts = block:
        var tmp = request.path.split('/')
        tmp.delete(0)
        tmp

      var matchedSomeRoute: bool
      for route in router.routes:
        if route.parts.len > pathParts.len:
          continue

        request.pathParams.setLen(0)

        var
          i: int
          matchedRoute = true
          atLeastOneMultiWildcardMatch = false
        for j, part in pathParts:
          if i >= route.parts.len:
            matchedRoute = false
            break

          if route.parts[i] == "*": # Wildcard segment
            inc i
          elif route.parts[i].len >= 2 and route.parts[i].startsWith('@'):
            # Named path parameter
            request.pathParams.add((route.parts[i][1 .. ^1], part))
            inc i
          elif route.parts[i] == "**": # Multi-segment wildcard
            # Do we have a required next literal?
            if i + 1 < route.parts.len and atLeastOneMultiWildcardMatch:
              let matchesNextLiteral =
                if route.parts[i + 1].isPartialWildcard():
                  partialWildcardMatches(route.parts[i + 1], part)
                else:
                  part == route.parts[i + 1]
              if matchesNextLiteral:
                i += 2
                atLeastOneMultiWildcardMatch = false
              elif j == pathParts.high:
                matchedRoute = false
                break
            else:
              atLeastOneMultiWildcardMatch = true
          elif route.parts[i].isPartialWildcard():
            if not partialWildcardMatches(route.parts[i], part):
              matchedRoute = false
              break
            inc i
          else: # Literal
            if part != route.parts[i]:
              matchedRoute = false
              break
            inc i

        if matchedRoute:
          matchedSomeRoute = true
          if request.httpMethod == route.httpMethod: # We have a winner
            route.handler(request)
            return

      if matchedSomeRoute: # We matched a route but not the HTTP method
        if router.methodNotAllowedHandler != nil:
          router.methodNotAllowedHandler(request)
        else:
          defaultMethodNotAllowedHandler(request)
      else:
        notFound()
    except:
      let e = getCurrentException()
      if router.errorHandler != nil:
        router.errorHandler(request, e)
      else:
        raise e

converter convertToHandler*(router: Router): RequestHandler =
  router.toHandler()
