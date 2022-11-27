import mummy {.all.}

block:
  var headers: HttpHeaders
  headers["1"] = "a,b"
  headers["2"] = "a, bbbb,cc  ,     dd   ,,"

  doAssert headers.headerContainsToken("1", "a")
  doAssert headers.headerContainsToken("1", "A")
  doAssert headers.headerContainsToken("1", "b")
  doAssert headers.headerContainsToken("1", "B")
  doAssert not headers.headerContainsToken("1", "c")
  doAssert not headers.headerContainsToken("1", "C")

  doAssert headers.headerContainsToken("2", "a")
  doAssert headers.headerContainsToken("2", "bbbb")
  doAssert headers.headerContainsToken("2", "BbBB")
  doAssert headers.headerContainsToken("2", "cc")
  doAssert headers.headerContainsToken("2", "dd")
  doAssert headers.headerContainsToken("2", "DD")
  doAssert not headers.headerContainsToken("2", "d")
