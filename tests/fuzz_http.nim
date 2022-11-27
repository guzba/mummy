include mummy

import std/random

randomize()

proc randomWhitespace(): string =
  let len = rand(0 ..< 10)
  for i in 0 ..< len:
    result &= ' '

block:
  echo "Fuzzing headerContainsToken"

  proc randomToken(): string =
    let len = rand(0 ..< 10)
    for i in 0 ..< len:
      var c: char
      while true:
        c = rand(33 .. 126).char
        if c != ','.char:
          break
      result &= c.char

  for i in 0 ..< 1000:
    var tokens: seq[seq[string]]
    tokens.setLen(10)

    var headers: HttpHeaders
    for i in 0 ..< 10:
      let numTokens = rand(0 ..< 10)
      if numTokens > 0:
        var v: string
        for j in 0 ..< numTokens:
          let token = randomToken()
          tokens[i].add(token)
          if j > 0:
            v &= randomWhitespace() & ','
          v &= randomWhitespace() & token
        headers[$i] = v
      else:
        let v = randomToken()
        tokens[i].add(v)
        headers[$i] = v

    for i in 0 ..< tokens.len:
      for j in 0 ..< tokens[i].len:
        if tokens[i][j].len > 0 and
          not headers.headerContainsToken($i, toLowerAscii(tokens[i][j])):
          echo "header: ", headers[$i]
          echo "token: ", tokens[i][j]
          doAssert false

block:
  echo "Fuzzing afterRecvHttp"

  proc randomAsciiString(): string =
    let len = rand(0 ..< 20)
    for i in 0 ..< len:
      result &= rand(33 .. 126).char

  proc randomHeader(): string =
    let len = rand(0 ..< 10)
    for i in 0 ..< len:
      var c: char
      while true:
        c = rand(33 .. 126).char
        if c != ':':
          break
      result &= c.char

  proc handler(request: Request) =
    discard

  let
    server = newServer(handler)
    clientSocket = 1.SocketHandle

  block:
    echo "Headers"

    for i in 0 ..< 1000:
      let handleData = HandleData()

      # Add request line
      var
        httpMethod = randomAsciiString()
        uri = randomAsciiString()
      handleData.recvBuffer.add(httpMethod)
      handleData.recvBuffer.add(' ')
      handleData.recvBuffer.add(uri)
      handleData.recvBuffer.add(' ')
      case rand(0 .. 2):
      of 0:
        handleData.recvBuffer.add(http10)
      of 1:
        handleData.recvBuffer.add(http11)
      else:
        handleData.recvBuffer.add(randomAsciiString())
      handleData.recvBuffer.add("\r\n")

      # Add headers
      let numHeaders = rand(1 ..< 10)
      var headers: seq[string]
      for i in 0 ..< numHeaders:
        let header = randomHeader()
        headers.add(header)
        handleData.recvBuffer.add(header)
        handleData.recvBuffer.add(":")
        handleData.recvBuffer.add(randomWhitespace())
        handleData.recvBuffer.add(randomAsciiString())
        handleData.recvBuffer.add(randomWhitespace())
        handleData.recvBuffer.add("\r\n")
      handleData.recvBuffer.add("\r\n")

      handleData.bytesReceived = handleData.recvBuffer.len

      var newRequests: seq[Request]
      let closingConnection = server.afterRecvHttp(
        clientSocket,
        handleData,
        newRequests
      )
      if not closingConnection:
        let request = newRequests[0]
        doAssert request.httpMethod == httpMethod
        doAssert request.uri == uri
        doAssert request.headers.len == numHeaders
        for i in 0 ..< numHeaders:
          doAssert headers[i] in request.headers

  block:
    echo "Transfer-Encoding: chunked"

    for i in 0 ..< 1000:
      let handleData = HandleData()

      handleData.recvBuffer.add("GET / HTTP/1.1\r\n")
      handleData.recvBuffer.add("Transfer-Encoding: chunked\r\n")
      handleData.recvBuffer.add("\r\n")

      var body: string
      for i in 0 ..< rand(1 ..< 1000):
        body &= randomAsciiString()

      var
        pos: int
        encoded: string
      while true:
        let chunkLen = min(rand(1 ..< 4096), body.len - pos)
        encoded &= toHex(chunkLen)
        encoded &= "\r\n"
        encoded &= body[pos ..< pos + chunkLen]
        encoded &= "\r\n"
        pos += chunkLen
        if chunkLen == 0:
          break

      handleData.recvBuffer.add(encoded)

      handleData.bytesReceived = handleData.recvBuffer.len

      # Add some junk the end
      handleData.recvBuffer.setLen(handleData.recvBuffer.len + rand(0 ..< 10))

      var newRequests: seq[Request]
      let closingConnection = server.afterRecvHttp(
        clientSocket,
        handleData,
        newRequests
      )
      if not closingConnection:
        let request = newRequests[0]
        doAssert request.headers.headerContainsToken(
          "Transfer-Encoding", "chunked"
        )
        doAssert request.body == body

  block:
    echo "Content-Length"

    for i in 0 ..< 1000:
      let handleData = HandleData()

      var body: string
      for i in 0 ..< rand(1 ..< 1000):
        body &= randomAsciiString()

      handleData.recvBuffer.add("GET / HTTP/1.1\r\n")
      handleData.recvBuffer.add("Content-Length: " & $body.len & "\r\n")
      handleData.recvBuffer.add("\r\n")
      handleData.recvBuffer.add(body)

      handleData.bytesReceived = handleData.recvBuffer.len

      # Add some junk the end
      handleData.recvBuffer.setLen(handleData.recvBuffer.len + rand(0 ..< 10))

      var newRequests: seq[Request]
      let closingConnection = server.afterRecvHttp(
        clientSocket,
        handleData,
        newRequests
      )
      if not closingConnection:
        let request = newRequests[0]
        doAssert request.headers.headerContainsToken(
          "Content-Length", $body.len
        )
        doAssert request.body == body
