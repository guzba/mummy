import mummy, mummy/multipart, std/strutils, std/typetraits, webby/urls

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
    handler2: RouteHandler

  RoutedRequest* = object
    internal: Request
    # httpVersion*: HttpVersion
    # httpMethod*: string
    # uri*: string
    # headers*: HttpHeaders
    # body*: string
    # remoteAddress*: string
    pathParams*: PathParams
    queryParams*: QueryParams

  RouteHandler* = proc(request: RoutedRequest) {.gcsafe.}

  PathParams* = distinct seq[(string, string)]

converter toBase*(params: var PathParams): var seq[(string, string)] =
  params.distinctBase

converter toBase*(params: PathParams): lent seq[(string, string)] =
  params.distinctBase

proc `[]`*(pathParams: PathParams, key: string): string =
  ## Returns the value for key, or an empty string if the key is not present.
  for (k, v) in pathParams.toBase:
    if k == key:
      return v

proc `[]=`*(pathParams: var PathParams, key, value: string) =
  ## Sets the value for the key. If the key is not present, this
  ## appends a new key-value pair to the end.
  for pair in pathParams.mitems:
    if pair[0] == key:
      pair[1] = value
      return
  pathParams.add((key, value))

proc contains*(pathParams: PathParams, key: string): bool =
  for pair in pathParams:
    if pair[0] == key:
      return true

proc getOrDefault*(pathParams: PathParams, key, default: string): string =
  if key in pathParams: pathParams[key] else: default

proc addRoute*(
  router: var Router,
  httpMethod, route: string | static string,
  handler: RequestHandler | RouteHandler
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

  when handler is RouteHandler:
    router.routes.add(Route(
      httpMethod: httpMethod,
      parts: move parts,
      handler2: handler
    ))
  else:
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

proc get*(
  router: var Router,
  route: string | static string,
  handler: RouteHandler
) =
  ## Adds a route for GET requests. See `addRoute` for more info.
  router.addRoute("GET", route, handler)

proc head*(
  router: var Router,
  route: string | static string,
  handler: RouteHandler
) =
  ## Adds a route for HEAD requests. See `addRoute` for more info.
  router.addRoute("HEAD", route, handler)

proc post*(
  router: var Router,
  route: string | static string,
  handler: RouteHandler
) =
  ## Adds a route for POST requests. See `addRoute` for more info.
  router.addRoute("POST", route, handler)

proc put*(
  router: var Router,
  route: string | static string,
  handler: RouteHandler
) =
  ## Adds a route for PUT requests. See `addRoute` for more info.
  router.addRoute("PUT", route, handler)

proc delete*(
  router: var Router,
  route: string | static string,
  handler: RouteHandler
) =
  ## Adds a route for DELETE requests. See `addRoute` for more info.
  router.addRoute("DELETE", route, handler)

proc options*(
  router: var Router,
  route: string | static string,
  handler: RouteHandler
) =
  ## Adds a route for OPTIONS requests. See `addRoute` for more info.
  router.addRoute("OPTIONS", route, handler)

proc patch*(
  router: var Router,
  route: string | static string,
  handler: RouteHandler
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

    if request.uri.len == 0 or request.uri[0] != '/':
      notFound()
      return

    try:
      var url =
        try:
          parseUrl(request.uri)
        except:
          notFound()
          return

      var routedRequest: RoutedRequest
      routedRequest.internal = request
      routedRequest.queryParams = move url.query

      let uriParts = block:
        var tmp = url.path.split('/')
        tmp.delete(0)
        tmp

      var matchedSomeRoute: bool
      for route in router.routes:
        if route.parts.len > uriParts.len:
          continue

        routedRequest.pathParams.setLen(0)

        var
          i: int
          matchedRoute = true
          atLeastOneMultiWildcardMatch = false
        for j, part in uriParts:
          if i >= route.parts.len:
            matchedRoute = false
            break

          if route.parts[i] == "*": # Wildcard segment
            inc i
          elif route.parts[i].len >= 2 and route.parts[i].startsWith('@'):
            # Named path parameter
            routedRequest.pathParams.add((route.parts[i][1 .. ^1], part))
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
              elif j == uriParts.high:
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
            if route.handler2 != nil:
              route.handler2(routedRequest)
            else:
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

proc `$`*(request: RoutedRequest): string {.inline.} =
  $request.internal

proc httpMethod*(request: RoutedRequest): lent string {.inline.} =
  request.internal.httpMethod

proc uri*(request: RoutedRequest): lent string {.inline.} =
  request.internal.uri

proc headers*(request: RoutedRequest): lent HttpHeaders {.inline.} =
  request.internal.headers

proc body*(request: RoutedRequest): lent string {.inline.} =
  request.internal.body

proc remoteAddress*(request: RoutedRequest): lent string {.inline.} =
  request.internal.remoteAddress

proc respond*(
  request: RoutedRequest,
  statusCode: int,
  headers: sink HttpHeaders = emptyHttpHeaders(),
  body: sink string = ""
) {.inline, raises: [], gcsafe.} =
  ## Sends the response for the request.
  ## This should usually only be called once per request.
  request.internal.respond(statusCode, move headers, move body)

proc upgradeToWebSocket*(
  request: RoutedRequest
): WebSocket {.inline, raises: [MummyError], gcsafe.} =
  ## Upgrades the request to a WebSocket connection. You can immediately start
  ## calling send().
  ## Future updates for this WebSocket will be calls to the websocketHandler
  ## provided to `newServer`. The first event will be onOpen.
  ## Note: if the client disconnects before receiving this upgrade response,
  ## no onOpen event will be received.
  request.internal.upgradeToWebSocket()

proc decodeMultipart*(
  request: RoutedRequest
): seq[MultipartEntry] {.raises: [MummyError].} =
  request.internal.decodeMultipart()
