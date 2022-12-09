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
    router.get("/**/**", handler)

  let routerHandler = router.toHandler()

  let request = cast[Request](allocShared0(sizeof(RequestObj)))
  request.httpMethod = "GET"

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

  request.uri = "/literalasdf#asdf"
  routerHandler(request)

  request.uri = "/adoubleb#asdf"
  routerHandler(request)

  request.uri = "/longerdoubleevenmore?a=b#asdf"
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

  request.uri = "/#asdf"
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
