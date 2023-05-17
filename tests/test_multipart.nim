import mummy, mummy/multipart

block:
  let request = cast[Request](allocShared0(sizeof(RequestObj)))
  doAssertRaises MummyError:
    discard request.decodeMultipart()

block:
  let request = cast[Request](allocShared0(sizeof(RequestObj)))
  request.body = "--123--"

  request.headers["Content-Type"] = "multipart/form-data; boundary=123"
  discard request.decodeMultipart()

  doAssertRaises MummyError:
    request.headers["Content-Type"] = "asdf; boundary=123"
    discard request.decodeMultipart()

  doAssertRaises MummyError:
    request.headers["Content-Type"] = "multipart/form-data; boundary="
    discard request.decodeMultipart()

  doAssertRaises MummyError:
    request.headers["Content-Type"] = "multipart/form-data; boundary=456"
    discard request.decodeMultipart()

  request.headers["Content-Type"] = "MULTIPART/FoRm-DaTa; boundary=123"
  discard request.decodeMultipart()

  request.headers["Content-Type"] = "multipart/form-data;boundary=123"
  discard request.decodeMultipart()

  request.headers["Content-Type"] = "multipart/form-data; boundary=\"123\""
  discard request.decodeMultipart()

  request.body = "--123--\r\n"
  discard request.decodeMultipart()

block:
  let request = cast[Request](allocShared0(sizeof(RequestObj)))
  request.headers["Content-Type"] = "multipart/form-data; boundary=123"

  block:
    request.body = "--123\r\nContent-Disposition: form-data; name=\"abc\"\r\n\r\n\r\n--123--"
    let entries = request.decodeMultipart()
    doAssert entries.len == 1
    doAssert entries[0].name == "abc"
    doAssert not entries[0].data.isSome
    doAssert entries[0].headers == @[("Content-Disposition", "form-data; name=\"abc\"")]

  block:
    request.body = "--123\r\nContent-Disposition: form-data; name=abc\r\n\r\n\r\n--123--"
    let entries = request.decodeMultipart()
    doAssert entries.len == 1
    doAssert entries[0].name == "abc"
    doAssert not entries[0].data.isSome

  block:
    request.body = "--123\r\nContent-Disposition: form-data; name=abc;zzz\r\n\r\n\r\n--123--"
    let entries = request.decodeMultipart()
    doAssert entries.len == 1
    doAssert entries[0].name == "abc"
    doAssert not entries[0].data.isSome

  block:
    request.body = "--123\r\nContent-Disposition: form-data; name=abc\r\n--123--"
    doAssertRaises MummyError:
      discard request.decodeMultipart()

  block:
    request.body = "--123\r\nContent-Disposition: name=\"abc\"\r\n\r\n\r\n--123--"
    doAssertRaises MummyError:
      discard request.decodeMultipart()

  block:
    request.body = "--123\r\n\r\n--123--"
    doAssertRaises MummyError:
      discard request.decodeMultipart()

  block:
    request.body = "--123\r\nContent-Disposition: form-data; name=abc\r\n\r\n--123--"
    doAssertRaises MummyError:
      echo request.decodeMultipart()

  block:
    request.body = "--123\r\nContent-Disposition: form-data; \r\n\r\n--123--"
    doAssertRaises MummyError:
      echo request.decodeMultipart()

  block:
    request.body = "--123\r\nContent-Disposition: form-data; name=\"abc\"\r\n\r\ndef\r\n--123--"
    let entries = request.decodeMultipart()
    doAssert entries.len == 1
    doAssert entries[0].name == "abc"
    doAssert not entries[0].filename.isSome
    doAssert entries[0].data.isSome
    let (start, last) = entries[0].data.get
    doAssert request.body[start .. last] == "def"

  block:
    request.body = "--123\r\nContent-Disposition: form-data; name=\"abc\";filename=\"file.txt\";\r\nContent-Type: text/plain\r\n\r\ndef\r\n--123\r\nContent-Disposition: form-data; name=\"ghi\"\r\nDummy-Header-1: 1\r\nDummy-Header-2: 2\r\nBroken-Header\r\n\r\njkl\r\n--123--"
    let entries = request.decodeMultipart()

    doAssert entries.len == 2
    doAssert entries[0].name == "abc"
    doAssert entries[0].filename == some("file.txt")
    doAssert entries[0].headers.len == 2
    doAssert entries[0].headers["Content-Type"] == "text/plain"
    doAssert entries[0].data.isSome
    block:
      let (start, last) = entries[0].data.get
      doAssert request.body[start .. last] == "def"

    doAssert entries[1].name == "ghi"
    doAssert entries[1].data.isSome
    block:
      let (start, last) = entries[1].data.get
      doAssert request.body[start .. last] == "jkl"
    doAssert entries[1].headers == @[
      ("Content-Disposition", "form-data; name=\"ghi\""),
      ("Dummy-Header-1", "1"),
      ("Dummy-Header-2", "2"),
      ("Broken-Header", "")
    ]
