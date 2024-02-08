import mummy {.all.}, mummy/internal

block:
  var headers: HttpHeaders
  headers["0"] = "a"
  headers["1"] = "a,b"
  headers["2"] = "a, bbbb,cc  ,     dd   ,,"

  doAssert headers.headerContainsToken("0", "a")
  doAssert headers.headerContainsToken("0", "A")
  doAssert not headers.headerContainsToken("0", "b")

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

block:
  for i in 0 ..< 10_000:
    doAssert strictParseInt($i) == i

  doAssert strictParseInt("-1") == -1

  doAssert strictParseInt("9223372036854775807") == 9223372036854775807
  doAssert strictParseInt("-9223372036854775808") == -9223372036854775808

  doAssertRaises ValueError:
    discard strictParseInt("")

  doAssertRaises ValueError:
    discard strictParseInt("+")

  doAssertRaises ValueError:
    discard strictParseInt("-")

  doAssertRaises ValueError:
    discard strictParseInt("-0")

  doAssertRaises ValueError:
    discard strictParseInt("+1")

  doAssertRaises ValueError:
    discard strictParseInt("010")

  doAssertRaises ValueError:
    discard strictParseInt("9223372036854775808")

  doAssertRaises ValueError:
    discard strictParseInt("-9223372036854775809")

block:
  doAssertRaises ValueError:
    discard strictParseHex("")

  doAssertRaises ValueError:
    discard strictParseHex("00")

  doAssertRaises ValueError:
    discard strictParseHex("0f")

  doAssertRaises ValueError:
    discard strictParseHex("0x1")

  for i in 0 ..< 10_000:
    doAssert strictParseHex(toHexWithoutLeadingZeroes(i)) == i

  doAssert strictParseHex("7FFFFFFFFFFFFFFF") == 9223372036854775807

  doAssertRaises ValueError:
    discard strictParseHex("8FFFFFFFFFFFFFFF")

  discard strictParseHex("1111111111111111")
  doAssertRaises ValueError:
    discard strictParseHex("11111111111111111")
