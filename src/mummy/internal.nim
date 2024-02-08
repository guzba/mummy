import common, std/nativesockets, webby/httpheaders, std/endians, std/strutils

template currentExceptionAsMummyError*(): untyped =
  let e = getCurrentException()
  newException(MummyError, e.getStackTrace & e.msg, e)

proc encodeFrameHeader*(
  opcode: uint8,
  payloadLen: int
): string {.raises: [], gcsafe.} =
  assert (opcode and 0b11110000) == 0

  # Calculate the frame header buffer len in advance to just do one allocation
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
    var l: uint64
    bigEndian64(l.addr, payloadLen.unsafeAddr)
    result.setLen(result.len + 8)
    copyMem(result[result.len - 8].addr, l.addr, 8)

proc encodeHeaders*(
  statusCode: int,
  headers: HttpHeaders
): string {.raises: [], gcsafe.} =
  let
    status =
      case statusCode:
      of 101:
        $statusCode & " Switching Protocols"
      else:
        $statusCode
    statusLineLen = 9 + status.len + 2

  # Calculate the header buffer len in advance to just do one allocation
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
    status[0].unsafeAddr,
    status.len
  )
  pos += status.len

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

template integerOutOfRangeError() =
  raise newException(ValueError, "Parsed integer outside of valid range")

template invalidDecimalIntegerError() =
  raise newException(ValueError, "Invalid integer decimal string")

template invalidHexError() =
  raise newException(ValueError, "Invalid hex string")

proc strictParseInt*(s: openarray[char]): int =
  var
    sign = -1
    i = 0

  if i < s.len and s[i] == '-':
    inc i
    sign = 1

  if i == s.len: # "-"
    invalidDecimalIntegerError()

  if i < s.len:
    if (i == 0 and s.len - i == 1 and s[i] == '0') or s[i] in {'1'..'9'}:
      result = 0
      while i < s.len and s[i] in {'0'..'9'}:
        let c = ord(s[i]) - ord('0')
        if result >= (int.low + c) div 10:
          result = result * 10 - c
        else:
          integerOutOfRangeError()
        inc i
      if sign == -1 and result == int.low:
        integerOutOfRangeError()
      else:
        result = result * sign

  if i == 0 or i != s.len:
    invalidDecimalIntegerError()

proc toHexWithoutLeadingZeroes*(i: int): string =
  if i == 0:
    return "0"
  result = toHex(i)
  for i, c in result:
    if c != '0':
      result = result[i .. ^1]
      break

proc strictParseHex*(s: openarray[char]): int =
  var
    i = 0
    bits: uint

  if s.len > 1 and s[i] == '0':
    invalidHexError()

  if s.len > 16:
    integerOutOfRangeError()

  while i < s.len:
    case s[i]
    of '0'..'9':
      bits = bits shl 4 or ord(s[i]).uint - ord('0').uint
    of 'a'..'f':
      bits = bits shl 4 or ord(s[i]).uint - ord('a').uint + 10.uint
    of 'A'..'F':
      bits = bits shl 4 or ord(s[i]).uint - ord('A').uint + 10.uint
    else:
      break
    inc i

  if i == 0 or i != s.len:
    invalidHexError()

  if bits > int.high.uint:
    integerOutOfRangeError()

  result = bits.int
