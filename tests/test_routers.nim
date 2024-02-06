import mummy, mummy/routers, webby/urls

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
  router.get("/質問/日本語のURLはどうする", handler)

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

  request.path = ""
  doAssertRaises AssertionDefect:
    routerHandler(request)

  request.path = "page.html"
  doAssertRaises AssertionDefect:
    routerHandler(request)

  request.path = "/"
  routerHandler(request)

  request.path = "/a"
  doAssertRaises AssertionDefect:
    routerHandler(request)

  request.path = "/page.html"
  routerHandler(request)

  request.path = "/script.js"
  routerHandler(request)

  request.path = "/.js"
  routerHandler(request)

  request.path = "/script.j"
  doAssertRaises AssertionDefect:
    routerHandler(request)

  request.path = "/script.html"
  doAssertRaises AssertionDefect:
    routerHandler(request)

  request.path = "/script"
  doAssertRaises AssertionDefect:
    routerHandler(request)

  request.path = "/min.js"
  routerHandler(request)

  request.path = "/index.html"
  doAssertRaises AssertionDefect:
    routerHandler(request)

  request.path = "/a/index.html"
  routerHandler(request)

  request.path = "/b/index.html"
  routerHandler(request)

  request.path = "/a/b/index.html"
  doAssertRaises AssertionDefect:
    routerHandler(request)

  request.path = "/styles/index.css"
  routerHandler(request)

  request.path = "/styles/2/index.css"
  doAssertRaises AssertionDefect:
    routerHandler(request)

  request.path = "/styles/script.js"
  doAssertRaises AssertionDefect:
    routerHandler(request)

  request.path = "/partial"
  doAssertRaises AssertionDefect:
    routerHandler(request)

  request.path = "/partial/something"
  routerHandler(request)

  request.path = "/partial/more/here"
  doAssertRaises AssertionDefect:
    routerHandler(request)

  request.path = "/literal*"
  routerHandler(request)

  request.path = "/literal*asdf&asdf"
  routerHandler(request)

  request.path = "/literalasdf"
  routerHandler(request)

  request.path = "/adoubleb"
  routerHandler(request)

  request.path = "/longerdoubleevenmore"
  routerHandler(request)

  request.path = "/doubleb"
  routerHandler(request)

  request.path = "/adouble"
  routerHandler(request)

  request.path = "/double"
  routerHandler(request)

  request.path = "/doubl"
  doAssertRaises AssertionDefect:
    routerHandler(request)

  block:
    let url = parseUrl("/%E8%B3%AA%E5%95%8F/%E6%97%A5%E6%9C%AC%E8%AA%9E%E3%81%AEURL%E3%81%AF%E3%81%A9%E3%81%86%E3%81%99%E3%82%8B")
    request.path = url.path
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

  request.path = "/"
  routerHandler(request)

  request.path = "/index.html"
  routerHandler(request)

  request.path = "/path"
  routerHandler(request)

  request.path = "/path/to/thing.html"
  routerHandler(request)

  request.path = "/a/b/c/d/e/f/g/h.txt"
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

  request.path = "/"
  doAssertRaises AssertionDefect:
    routerHandler(request)

  request.path = "/TEST/page.html"
  doAssertRaises AssertionDefect:
    routerHandler(request)

  request.path = "/TEST/a/b/c/d.html"
  doAssertRaises AssertionDefect:
    routerHandler(request)

  request.path = "/a/TEST/b.html"
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

  request.path = "/"
  doAssertRaises AssertionDefect:
    routerHandler(request)

  request.path = "/index.html"
  doAssertRaises AssertionDefect:
    routerHandler(request)

  request.path = "/path"
  doAssertRaises AssertionDefect:
    routerHandler(request)

  request.path = "/path/to/thing.html"
  doAssertRaises AssertionDefect:
    routerHandler(request)

  request.path = "/a/b/c/d/e/f/g/h.txt"
  doAssertRaises AssertionDefect:
    routerHandler(request)

  request.path = "/a/b/TEST/d/f/g.html"
  doAssertRaises AssertionDefect:
    routerHandler(request)

  request.path = "/a/TEST/page.html"
  doAssertRaises AssertionDefect:
    routerHandler(request)

  request.path = "/a/b/TEST/d/f/g/TEST2/page.html"
  routerHandler(request)

  request.path = "/a/TEST/b/TEST2/page.html"
  routerHandler(request)

  request.path = "/TEST/page.html&3"
  doAssertRaises AssertionDefect:
    routerHandler(request)

  request.path = "/TEST/TEST2/"
  doAssertRaises AssertionDefect:
    routerHandler(request)

  request.path = "/TEST/TEST2/page.html"
  doAssertRaises AssertionDefect:
    routerHandler(request)

  request.path = "/a/TEST/TEST2/"
  doAssertRaises AssertionDefect:
    routerHandler(request)

  request.path = "/a/TEST/TEST2/page.html"
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

  request.path = "/"
  doAssertRaises AssertionDefect:
    routerHandler(request)

  request.path = "/page/thing/do.html"
  routerHandler(request)

  request.path = "/2page/thing/do.html"
  routerHandler(request)

  request.path = "/wowpage/do.html"
  doAssertRaises AssertionDefect:
    routerHandler(request)

  request.path = "/wowpage/a/do.htm"
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

  request.path = "/a"
  routerHandler(request)

  request.path = "/aa"
  routerHandler(request)

  request.path = "/somethinga"
  routerHandler(request)

  request.path = "/a/"
  doAssertRaises AssertionDefect:
    routerHandler(request)

  request.path = "/something"
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

  request.path = "/something"
  routerHandler(request)

  request.path = "/asomething"
  routerHandler(request)

  request.path = "/somethingb"
  routerHandler(request)

  request.path = "/asomethingb"
  routerHandler(request)

  request.path = "/something/"
  doAssertRaises AssertionDefect:
    routerHandler(request)

  request.path = "/something/else"
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

  request.path = "/a"
  doAssertRaises AssertionDefect:
    routerHandler(request)

  request.path = "/ab"
  doAssertRaises AssertionDefect:
    routerHandler(request)

  request.path = "/asomethingb"
  doAssertRaises AssertionDefect:
    routerHandler(request)

  request.path = "/a*b"
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

  request.path = "/a"
  doAssertRaises AssertionDefect:
    routerHandler(request)

  request.path = "/ab"
  doAssertRaises AssertionDefect:
    routerHandler(request)

  request.path = "/asomethingb"
  doAssertRaises AssertionDefect:
    routerHandler(request)

  request.path = "/a**b"
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

  proc routeHandler1(request: Request) =
    doAssert "id" in request.pathParams
    doAssert request.pathParams.len == 1
    doAssert request.pathParams["id"] == "123"

  router.get("/@id", routeHandler1)

  proc routeHandler2(request: Request) =
    doAssert "name" in request.pathParams
    doAssert "id" in request.pathParams
    doAssert request.pathParams.len == 2
    doAssert request.pathParams["name"] == "abc"
    doAssert request.pathParams["id"] == "123"

  router.get("/@name/@id", routeHandler2)

  proc routeHandler3(request: Request) =
    doAssert "first" in request.pathParams
    doAssert "second" in request.pathParams
    doAssert request.pathParams.len == 2
    doAssert request.pathParams["first"] == "a"
    doAssert request.pathParams["second"] == "b"

  router.get("/@first/zzz/@second", routeHandler3)

  proc routeHandler4(request: Request) =
    doAssert "first" in request.pathParams
    doAssert "second" in request.pathParams
    doAssert request.pathParams.len == 2
    doAssert request.pathParams["first"] == "a"
    doAssert request.pathParams["second"] == "b"

  router.get("/@first/*/@second", routeHandler4)

  let routerHandler = router.toHandler()

  let request = cast[Request](allocShared0(sizeof(RequestObj)))
  request.httpMethod = "GET"

  request.path = "/123"
  routerHandler(request)

  request.path = "/abc/123"
  routerHandler(request)

  request.path = "/a/zzz/b"
  routerHandler(request)

  request.path = "/a/wild/b"
  routerHandler(request)
