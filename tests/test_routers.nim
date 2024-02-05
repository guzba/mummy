import mummy, mummy/routers

proc handler(request: Request) =
  discard

block:
  var router: Router
  router.notFoundHandler = proc(request: Request) =
    doAssert false
  router.methodNotAllowedHandler = proc(request: Request) =
    doAssert false
  router.errorHandler = proc(request: Request, e: ref Exception) =
    doAssert false

  router.get("/", handler)
  router.get("/page.html", handler)
  router.get("/*.js", handler)
  router.get("/*/index.html", handler)
  router.get("/styles/*.css", handler)
  router.get("/partial/*", handler)
  router.get("/literal*", handler)
  router.get("/*double*", handler)

  doAssertRaises MummyError:
    router.get("/**/*", handler)

  doAssertRaises MummyError:
    router.get("/**/**", handler)

  doAssertRaises MummyError:
    router.get("/**/bad/**/**", handler)

  doAssertRaises MummyError:
    let s = ""
    router.get(s, handler)

  doAssertRaises MummyError:
    let s = "abc"
    router.get(s, handler)

  let routerHandler = router.toHandler()

  let request = cast[Request](allocShared0(sizeof(RequestObj)))
  request.httpMethod = "GET"

  request.uri = ""
  doAssertRaises AssertionDefect:
    routerHandler(request)

  request.uri = "page.html"
  doAssertRaises AssertionDefect:
    routerHandler(request)

  request.uri = "/"
  routerHandler(request)

  request.uri = "/a"
  doAssertRaises AssertionDefect:
    routerHandler(request)

  request.uri = "/page.html"
  routerHandler(request)

  request.uri = "/script.js"
  routerHandler(request)

  request.uri = "/.js"
  routerHandler(request)

  request.uri = "/script.j"
  doAssertRaises AssertionDefect:
    routerHandler(request)

  request.uri = "/script.html"
  doAssertRaises AssertionDefect:
    routerHandler(request)

  request.uri = "/script"
  doAssertRaises AssertionDefect:
    routerHandler(request)

  request.uri = "/min.js"
  routerHandler(request)

  request.uri = "/index.html"
  doAssertRaises AssertionDefect:
    routerHandler(request)

  request.uri = "/a/index.html"
  routerHandler(request)

  request.uri = "/b/index.html"
  routerHandler(request)

  request.uri = "/a/b/index.html"
  doAssertRaises AssertionDefect:
    routerHandler(request)

  request.uri = "/styles/index.css"
  routerHandler(request)

  request.uri = "/styles/2/index.css"
  doAssertRaises AssertionDefect:
    routerHandler(request)

  request.uri = "/styles/script.js"
  doAssertRaises AssertionDefect:
    routerHandler(request)

  request.uri = "/partial"
  doAssertRaises AssertionDefect:
    routerHandler(request)

  request.uri = "/partial/something"
  routerHandler(request)

  request.uri = "/partial/more/here?asdf=true"
  doAssertRaises AssertionDefect:
    routerHandler(request)

  request.uri = "/literal*"
  routerHandler(request)

  request.uri = "/literal*asdf&asdf"
  routerHandler(request)

  request.uri = "/literalasdf"
  routerHandler(request)

  request.uri = "/adoubleb"
  routerHandler(request)

  request.uri = "/longerdoubleevenmore?a=b"
  routerHandler(request)

  request.uri = "/doubleb"
  routerHandler(request)

  request.uri = "/adouble"
  routerHandler(request)

  request.uri = "/double"
  routerHandler(request)

  request.uri = "/doubl"
  doAssertRaises AssertionDefect:
    routerHandler(request)

  deallocShared(request)

block:
  var router: Router
  router.notFoundHandler = proc(request: Request) =
    doAssert false
  router.methodNotAllowedHandler = proc(request: Request) =
    doAssert false
  router.errorHandler = proc(request: Request, e: ref Exception) =
    doAssert false

  proc badHandler(request: Request) =
    doAssert false

  router.get("/**", handler)
  router.get("/**", badHandler)

  let routerHandler = router.toHandler()

  let request = cast[Request](allocShared0(sizeof(RequestObj)))
  request.httpMethod = "GET"

  request.uri = "/"
  routerHandler(request)

  request.uri = "/index.html"
  routerHandler(request)

  request.uri = "/path"
  routerHandler(request)

  request.uri = "/path/to/thing.html"
  routerHandler(request)

  request.uri = "/a/b/c/d/e/f/g/h.txt"
  routerHandler(request)

block:
  var router: Router
  router.notFoundHandler = proc(request: Request) =
    doAssert false
  router.methodNotAllowedHandler = proc(request: Request) =
    doAssert false
  router.errorHandler = proc(request: Request, e: ref Exception) =
    doAssert false

  router.get("/**/TEST/**", handler)

  let routerHandler = router.toHandler()

  let request = cast[Request](allocShared0(sizeof(RequestObj)))
  request.httpMethod = "GET"

  request.uri = "/"
  doAssertRaises AssertionDefect:
    routerHandler(request)

  request.uri = "/TEST/page.html"
  doAssertRaises AssertionDefect:
    routerHandler(request)

  request.uri = "/TEST/a/b/c/d.html"
  doAssertRaises AssertionDefect:
    routerHandler(request)

  request.uri = "/a/TEST/b.html"
  routerHandler(request)

block:
  var router: Router
  router.notFoundHandler = proc(request: Request) =
    doAssert false
  router.methodNotAllowedHandler = proc(request: Request) =
    doAssert false
  router.errorHandler = proc(request: Request, e: ref Exception) =
    doAssert false

  router.get("/**/TEST/**/TEST2/**", handler)

  let routerHandler = router.toHandler()

  let request = cast[Request](allocShared0(sizeof(RequestObj)))
  request.httpMethod = "GET"

  request.uri = "/"
  doAssertRaises AssertionDefect:
    routerHandler(request)

  request.uri = "/index.html"
  doAssertRaises AssertionDefect:
    routerHandler(request)

  request.uri = "/path"
  doAssertRaises AssertionDefect:
    routerHandler(request)

  request.uri = "/path/to/thing.html"
  doAssertRaises AssertionDefect:
    routerHandler(request)

  request.uri = "/a/b/c/d/e/f/g/h.txt"
  doAssertRaises AssertionDefect:
    routerHandler(request)

  request.uri = "/a/b/TEST/d/f/g.html"
  doAssertRaises AssertionDefect:
    routerHandler(request)

  request.uri = "/a/TEST/page.html"
  doAssertRaises AssertionDefect:
    routerHandler(request)

  request.uri = "/a/b/TEST/d/f/g/TEST2/page.html"
  routerHandler(request)

  request.uri = "/a/TEST/b/TEST2/page.html"
  routerHandler(request)

  request.uri = "/TEST/page.html&3"
  doAssertRaises AssertionDefect:
    routerHandler(request)

  request.uri = "/TEST/TEST2/"
  doAssertRaises AssertionDefect:
    routerHandler(request)

  request.uri = "/TEST/TEST2/page.html"
  doAssertRaises AssertionDefect:
    routerHandler(request)

  request.uri = "/a/TEST/TEST2/"
  doAssertRaises AssertionDefect:
    routerHandler(request)

  request.uri = "/a/TEST/TEST2/page.html"
  doAssertRaises AssertionDefect:
    routerHandler(request)

block:
  var router: Router
  router.notFoundHandler = proc(request: Request) =
    doAssert false
  router.methodNotAllowedHandler = proc(request: Request) =
    doAssert false
  router.errorHandler = proc(request: Request, e: ref Exception) =
    doAssert false

  router.get("/*page/**/*.html", handler)

  let routerHandler = router.toHandler()

  let request = cast[Request](allocShared0(sizeof(RequestObj)))
  request.httpMethod = "GET"

  request.uri = "/"
  doAssertRaises AssertionDefect:
    routerHandler(request)

  request.uri = "/page/thing/do.html"
  routerHandler(request)

  request.uri = "/2page/thing/do.html"
  routerHandler(request)

  request.uri = "/wowpage/do.html"
  doAssertRaises AssertionDefect:
    routerHandler(request)

  request.uri = "/wowpage/a/do.htm"
  doAssertRaises AssertionDefect:
    routerHandler(request)

block:
  var router: Router
  router.notFoundHandler = proc(request: Request) =
    doAssert false
  router.methodNotAllowedHandler = proc(request: Request) =
    doAssert false
  router.errorHandler = proc(request: Request, e: ref Exception) =
    doAssert false

  router.get("/*a", handler)

  let routerHandler = router.toHandler()

  let request = cast[Request](allocShared0(sizeof(RequestObj)))
  request.httpMethod = "GET"

  request.uri = "/a"
  routerHandler(request)

  request.uri = "/aa"
  routerHandler(request)

  request.uri = "/somethinga"
  routerHandler(request)

  request.uri = "/a/"
  doAssertRaises AssertionDefect:
    routerHandler(request)

  request.uri = "/something"
  doAssertRaises AssertionDefect:
    routerHandler(request)

block:
  var router: Router
  router.notFoundHandler = proc(request: Request) =
    doAssert false
  router.methodNotAllowedHandler = proc(request: Request) =
    doAssert false
  router.errorHandler = proc(request: Request, e: ref Exception) =
    doAssert false

  router.get("/*something*", handler)

  let routerHandler = router.toHandler()

  let request = cast[Request](allocShared0(sizeof(RequestObj)))
  request.httpMethod = "GET"

  request.uri = "/something"
  routerHandler(request)

  request.uri = "/asomething"
  routerHandler(request)

  request.uri = "/somethingb"
  routerHandler(request)

  request.uri = "/asomethingb"
  routerHandler(request)

  request.uri = "/something/"
  doAssertRaises AssertionDefect:
    routerHandler(request)

  request.uri = "/something/else"
  doAssertRaises AssertionDefect:
    routerHandler(request)

block:
  var router: Router
  router.notFoundHandler = proc(request: Request) =
    doAssert false
  router.methodNotAllowedHandler = proc(request: Request) =
    doAssert false
  router.errorHandler = proc(request: Request, e: ref Exception) =
    doAssert false

  router.get("/a*b", handler) # Not a wildcard here

  let routerHandler = router.toHandler()

  let request = cast[Request](allocShared0(sizeof(RequestObj)))
  request.httpMethod = "GET"

  request.uri = "/a"
  doAssertRaises AssertionDefect:
    routerHandler(request)

  request.uri = "/ab"
  doAssertRaises AssertionDefect:
    routerHandler(request)

  request.uri = "/asomethingb"
  doAssertRaises AssertionDefect:
    routerHandler(request)

  request.uri = "/a*b"
  routerHandler(request)

block:
  var router: Router
  router.notFoundHandler = proc(request: Request) =
    doAssert false
  router.methodNotAllowedHandler = proc(request: Request) =
    doAssert false
  router.errorHandler = proc(request: Request, e: ref Exception) =
    doAssert false

  router.get("/**z", handler) # Not a wildcard here
  router.get("/a**b", handler) # Not a wildcard here

  let routerHandler = router.toHandler()

  let request = cast[Request](allocShared0(sizeof(RequestObj)))
  request.httpMethod = "GET"

  request.uri = "/a"
  doAssertRaises AssertionDefect:
    routerHandler(request)

  request.uri = "/ab"
  doAssertRaises AssertionDefect:
    routerHandler(request)

  request.uri = "/asomethingb"
  doAssertRaises AssertionDefect:
    routerHandler(request)

  request.uri = "/a**b"
  routerHandler(request)

block:
  var pathParams: PathParams

  doAssert "foo" notin pathParams

  pathParams["foo"] = "bar"

  doAssert "foo" in pathParams

  doAssert pathParams.len == 1

  doAssert pathParams["foo"] == "bar"

block:
  var router: Router
  router.notFoundHandler = proc(request: Request) =
    doAssert false
  router.methodNotAllowedHandler = proc(request: Request) =
    doAssert false
  router.errorHandler = proc(request: Request, e: ref Exception) =
    doAssert false

  proc routeHandler1(request: RoutedRequest) =
    doAssert "id" in request.pathParams
    doAssert request.pathParams.len == 1
    doAssert request.pathParams["id"] == "123"

  router.get("/1/@id", routeHandler1)

  proc routeHandler2(request: RoutedRequest) =
    doAssert "name" in request.pathParams
    doAssert "id" in request.pathParams
    doAssert request.pathParams.len == 2
    doAssert request.pathParams["name"] == "abc"
    doAssert request.pathParams["id"] == "123"

  router.get("/2/@name/@id", routeHandler2)

  let routerHandler = router.toHandler()

  let request = cast[Request](allocShared0(sizeof(RequestObj)))
  request.httpMethod = "GET"

  request.uri = "/1"
  doAssertRaises AssertionDefect:
    routerHandler(request)

  request.uri = "/1/123"
  routerHandler(request)

  request.uri = "/2/abc/123"
  routerHandler(request)
