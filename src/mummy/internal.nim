import common, std/nativesockets, webby/httpheaders

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
  let
    statusCode = $statusCode
    statusLineLen = 9 + statusCode.len + 2

  var headersLen = statusLineLen
  for (k, v) in headers:
    # k + ": " + v + "\r\n"
    headersLen += k.len + 2 + v.len + 2
  # "\r\n"
  headersLen += 2

  result = newString(headersLen)
  result[0] = 'H'
  result[1] = 'T'
  result[2] = 'T'
  result[3] = 'P'
  result[4] = '/'
  result[5] = '1'
  result[6] = '.'
  result[7] = '1'
  result[8] = ' '

  var pos = 9
  copyMem(
    result[pos].addr,
    statusCode[0].unsafeAddr,
    statusCode.len
  )
  pos += statusCode.len

  result[pos + 0] = '\r'
  result[pos + 1] = '\n'
  pos += 2

  for (k, v) in headers:
    copyMem(
      result[pos].addr,
      k.cstring,
      k.len
    )
    pos += k.len

    result[pos + 0] = ':'
    result[pos + 1] = ' '
    pos += 2

    copyMem(
      result[pos].addr,
      v.cstring,
      v.len
    )
    pos += v.len

    result[pos + 0] = '\r'
    result[pos + 1] = '\n'
    pos += 2

  result[pos + 0] = '\r'
  result[pos + 1] = '\n'
  pos += 2
