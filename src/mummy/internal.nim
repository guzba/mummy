import common, std/nativesockets

template currentExceptionAsMummyError*(): untyped =
  let e = getCurrentException()
  newException(MummyError, e.getStackTrace & e.msg, e)

proc encodeFrameHeader*(
  opcode: uint8,
  payloadLen: int
): string {.raises: [], gcsafe.} =
  assert (opcode and 0b11110000) == 0

  var frameHeaderLen = 2

  if payloadLen <= 125:
    discard
  elif payloadLen <= uint16.high.int:
    frameHeaderLen += 2
  else:
    frameHeaderLen += 8

  result = newStringOfCap(frameHeaderLen)
  result.add cast[char](0b10000000 or opcode)

  if payloadLen <= 125:
    result.add payloadLen.char
  elif payloadLen <= uint16.high.int:
    result.add 126.char
    var l = cast[uint16](payloadLen).htons
    result.setLen(result.len + 2)
    copyMem(result[result.len - 2].addr, l.addr, 2)
  else:
    result.add 127.char
    var l = cast[uint32](payloadLen).htonl
    result.setLen(result.len + 8)
    copyMem(result[result.len - 4].addr, l.addr, 4)

proc encodeHeaders*(
  statusCode: int,
  headers: HttpHeaders
): string {.raises: [], gcsafe.} =
  let statusLine = "HTTP/1.1 " & $statusCode & "\r\n"

  var headersLen = statusLine.len
  for (k, v) in headers:
    # k + ": " + v + "\r\n"
    headersLen += k.len + 2 + v.len + 2
  # "\r\n"
  headersLen += 2

  result = newStringOfCap(headersLen)
  result.add statusLine

  for (k, v) in headers:
    result.add k & ": " & v & "\r\n" # Optimizable

  result.add "\r\n"
