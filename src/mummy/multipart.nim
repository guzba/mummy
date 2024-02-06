import ../mummy, std/strutils, std/options

export options

type MultipartEntry* = object
  name*: string
  filename*: Option[string]
  data*: Option[(int, int)] ## The (start, last) of this entry's data in the request body.
  headers*: HttpHeaders

proc decodeMultipart*(request: Request): seq[MultipartEntry] {.raises: [MummyError].} =

  template raiseInvalidContentType() =
    raise newException(MummyError, "Invalid Content-Type header for multipart")

  template raiseInvalidBody(extra = "") =
    var msg = "Invalid multipart body"
    if extra != "":
      msg &= ", " & extra
    raise newException(MummyError, move msg)

  var contentType = request.headers["Content-Type"]

  # Wolfram HTTPClient in Wolfram Language uses a comma instead of
  # a semicolon: multipart/form-data, boundary=vTd41rxm1e7O
  if request.headers["User-Agent"].startsWith("Wolfram HTTPClient"):
    contentType = contentType.replace(
      "multipart/form-data,",
      "multipart/form-data;"
    )

  let first = contentType.split(';', maxsplit = 1)

  if cmpIgnoreCase(first[0], "multipart/form-data") != 0 or first.len != 2:
    raiseInvalidContentType()

  let second = first[1].split("boundary=", maxsplit = 1)

  if second.len != 2:
    raiseInvalidContentType()

  var boundary = second[1]
  if boundary.len >= 2:
    # Remove quotes from around boundary if present
    # https://www.rfc-editor.org/rfc/rfc2046.html#section-5.1.1
    if boundary[0] == '"' and boundary[^1] == '"':
      boundary = boundary[1 ..< ^1]

  if boundary.len == 0:
    raiseInvalidContentType()

  let realBoundary = "--" & boundary

  var i: int
  while true:
    # Decodes one entry per iteration
    var entry: MultipartEntry

    # Ensure we have room for a boundary line
    if i + realBoundary.len + 2 > request.body.len:
      raiseInvalidBody("no room for boundary line")

    # Each entry must start with a boundary
    if not equalMem(
      request.body[i].addr,
      realBoundary.cstring,
      realBoundary.len
    ):
      raiseInvalidBody("entry does not start with boundary")

    i += realBoundary.len

    # Is this the multipart end marker?
    if request.body[i] == '-' and request.body[i + 1] == '-':
      i += 2
      # We should be at the end of the request body
      if i == request.body.len:
        break
      # If we are not, allow \r\n at the end of the request body
      if request.body.len == i + 2:
        if request.body[i] == '\r' and request.body[i + 1] == '\n':
          break
      # Something is wrong
      raiseInvalidBody("error with multipart body end marker")

    # This is a multipart entry

    # Ensure the boundary line ends with \r\n
    if request.body[i] != '\r' or request.body[i + 1] != '\n':
      raiseInvalidBody("boundary line does not end with \\r\\n")

    i += 2

    block: # Entry headers
      while true:
        let lineEnd = request.body.find("\r\n", start = i)
        if lineEnd == -1:
          raiseInvalidBody("header line does not end with \\r\\n")

        if lineEnd == i:
          # No more headers
          i += 2
          break

        # A header line
        let
          header = request.body[i ..< lineEnd]
          parts = header.split(':', maxsplit = 1)
        if parts.len == 2:
          entry.headers.add((parts[0].strip(), parts[1].strip()))
        else:
          # Malformed header, include it for debugging purposes
          entry.headers.add((header, ""))

        i = lineEnd + 2

    # Entry data here

    let nextBoundary = request.body.find(realBoundary, start = i)
    if nextBoundary == -1:
      raiseInvalidBody("entry missing next boundary")

    let
      start = i
      last = nextBoundary - 3

    if start <= last:
      entry.data = some((start, last))
    elif start - last == 1:
      # No data for this entry
      discard
    else:
      # Something wrong here
      raiseInvalidBody("entry data multipart end error")

    # Verify the \r\n after the entry data
    if request.body[last + 1] != '\r' or request.body[last + 2] != '\n':
      raiseInvalidBody("entry data does not end with \\r\\n")

    i = nextBoundary

    result.add(move entry)

  template raiseInvalidContentDisposition() =
    raise newException(MummyError, "Invalid Content-Disposition header")

  proc formDataValue(contentDisposition, name: string): Option[string] =
    var nameStart = contentDisposition.find(name & "=")
    if nameStart == -1:
      return none(string)
    nameStart += name.len + 1 # Move past name=
    if nameStart + 1 > contentDisposition.len:
      return none(string)
    # Is the name value quoted? name="abc" vs name=abc
    if contentDisposition[nameStart] == '"':
      let closeQuote = contentDisposition.find('"', start = nameStart + 1)
      if closeQuote == -1:
        raiseInvalidContentDisposition()
      result = some(contentDisposition[nameStart + 1 ..< closeQuote])
    else:
      let endingSemicolon = contentDisposition.find(';', start = nameStart)
      if endingSemicolon == -1:
        result = some(contentDisposition[nameStart .. ^1])
      else:
        result = some(contentDisposition[nameStart ..< endingSemicolon])

  for entry in result.mitems:
    let contentDisposition = entry.headers["Content-Disposition"]
    if contentDisposition.len < 10:
      raiseInvalidContentDisposition()
    if cmpIgnoreCase(contentDisposition[0 ..< 10], "form-data;") != 0:
      raiseInvalidContentDisposition()
    var entryName = contentDisposition.formDataValue("name")
    if not entryName.isSome:
      raiseInvalidContentDisposition() # A name is required
    entry.name = move entryName.get
    entry.filename = contentDisposition.formDataValue("filename")
