import std/base64, std/cpuinfo, std/deques, std/locks, std/nativesockets, std/os,
    std/parseutils, std/selectors, std/sets, std/sha1, std/strutils

export Port

const
  listenBacklogLen = 128
  maxEventsPerSelectLoop = 32
  initialRecvBufferLen = (32 * 1024) - 9 # 8 byte cap field + null terminator

type
  HttpServerError* = object of CatchableError

  HttpVersion* = enum
    Http10, Http11

  HttpHandler* = proc(request: HttpRequest, response: var HttpResponse)

  WebSocketHandler* = proc(websocket: WebSocket)

  HttpServer* = ref HttpServerObj

  HttpServerObj = object
    handler: HttpHandler
    websocketHander: WebSocketHandler
    maxHeadersLen, maxBodyLen: int
    workerThreads: seq[Thread[ptr HttpServerObj]]
    running: bool
    socket: SocketHandle
    selector: Selector[SocketState]
    responseReady: SelectEvent
    clientSockets: HashSet[SocketHandle]
    requestQueue: Deque[HttpRequest]
    requestQueueLock: Lock
    requestQueueCond: Cond
    responseQueue: Deque[EncodedHttpResponse]
    responseQueueLock: Lock
    nextWebSocketId: uint64

  SocketState = ref object
    recvBuffer: string
    bytesReceived: int
    requestState: IncomingRequestState
    msgState: IncomingWsMsgState
    outgoingPayloads: Deque[OutgoingPayloadState]
    upgradedToWebSocket, closeFrameSent: bool

  IncomingRequestState = object
    headersParsed, chunked: bool
    contentLength: int
    httpVersion: HttpVersion
    httpMethod, uri: string
    headers: HttpHeaders
    body: string

  IncomingWsMsgState = object
    opcode: uint8
    buffer: string
    msgLen: int

  OutgoingPayloadState = ref object
    closeConnection: bool
    buffer: string
    bytesSent: int

  HttpHeaders* = seq[(string, string)]

  HttpRequest* = ref object
    httpMethod*: string
    uri*: string
    headers*: HttpHeaders
    body*: string
    server: ptr HttpServerObj
    clientSocket: SocketHandle
    httpVersion: HttpVersion

  HttpResponse* = object
    statusCode*: int
    headers*: HttpHeaders
    body*: string
    websocketUpgrade: bool

  EncodedHttpResponse = ref object
    clientSocket: SocketHandle
    websocketUpgrade, closeConnection: bool
    buffer: string

  WebSocket* = object
    id: uint64
    server: ptr HttpServerObj
    clientSocket: SocketHandle

  WsMsgKind* = enum
    TextMsg, BinaryMsg

  WsMsg* = ref object
    kind: WsMsgKind
    data: string

# proc `$`*(request: HttpRequest) =
#   discard

# proc `$`*(response: var HttpResponse) =
#   discard

# proc `$`*(websocket: WebSocket) =
#   discard

template currentExceptionAsHttpServerError(): untyped =
  let e = getCurrentException()
  newException(HttpServerError, e.getStackTrace & e.msg, e)

proc contains*(headers: var HttpHeaders, key: string): bool =
  ## Checks if there is at least one header for the key. Not case sensitive.
  for (k, v) in headers:
    if cmpIgnoreCase(k, key) == 0:
      return true

proc `[]`*(headers: var HttpHeaders, key: string): string =
  ## Returns the first header value the key. Not case sensitive.
  for (k, v) in headers:
    if cmpIgnoreCase(k, key) == 0:
      return v

proc `[]=`*(headers: var HttpHeaders, key, value: string) =
  ## Adds a new header if the key is not already present. If the key is already
  ## present this overrides the first header value for the key.
  ## Not case sensitive.
  for i, (k, v) in headers:
    if cmpIgnoreCase(k, key) == 0:
      headers[i][1] = value
      return
  headers.add((key, value))

proc headerContainsToken(headers: var HttpHeaders, key, token: string): bool =
  for (k, v) in headers:
    if cmpIgnoreCase(k, key) == 0:
      if ',' in v:
        var parts = v.split(",")
        for part in parts.mitems:
          if cmpIgnoreCase(part.strip(), token) == 0:
            return true
      else:
        if cmpIgnoreCase(v, token) == 0:
          return true

proc updateHandle2(
  selector: Selector[SocketState],
  socket: SocketHandle,
  events: set[Event]
) {.raises: [IOSelectorsException].} =
  try:
    selector.updateHandle(socket, events)
  except ValueError: # Why ValueError?
    raise newException(IOSelectorsException, getCurrentExceptionMsg())

proc send*(
  websocket: WebSocket,
  data: string,
  kind = TextMsg,
) {.raises: [], gcsafe.} =
  discard

proc close*(websocket: WebSocket) {.raises: [], gcsafe.} =
  discard

proc websocketUpgrade*(
  request: HttpRequest,
  response: var HttpResponse
): WebSocket {.raises: [HttpServerError], gcsafe.} =
  if not request.headers.headerContainsToken("Connection", "upgrade"):
    raise newException(
      HttpServerError,
      "Invalid request to upgade, missing 'Connection: upgrade' header"
    )

  if not request.headers.headerContainsToken("Upgrade", "websocket"):
    raise newException(
      HttpServerError,
      "Invalid request to upgade, missing 'Upgrade: websocket' header"
    )

  let websocketKey = request.headers["Sec-WebSocket-Key"]
  if websocketKey == "":
    raise newException(
      HttpServerError,
      "Invalid request to upgade, missing Sec-WebSocket-Key header"
    )

  let websocketVersion = request.headers["Sec-WebSocket-Version"]
  if websocketVersion != "13":
    raise newException(
      HttpServerError,
      "Invalid request to upgade, missing Sec-WebSocket-Version header"
    )

  let hash =
    secureHash(websocketKey & "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").Sha1Digest

  response.websocketUpgrade = true
  response.statusCode = 101
  response.headers["Connection"] = "upgrade"
  response.headers["Upgrade"] = "websocket"
  response.headers["Sec-WebSocket-Accept"] = base64.encode(hash)

  result.server = request.server
  result.clientSocket = request.clientSocket

proc encodeFrame(opcode: uint8, data: string): string {.raises: [], gcsafe.} =
  assert (opcode and 0b11110000) == 0

  var frameLen = 2

  if data.len <= 125:
    discard
  elif data.len <= uint16.high.int:
    frameLen += 2
  else:
    frameLen += 8

  frameLen += data.len

  result = newStringOfCap(frameLen)
  result.add cast[char](0b10000000 or opcode)

  if data.len <= 125:
    result.add data.len.char
  elif data.len <= uint16.high.int:
    result.add 126.char
    var l = cast[uint16](data.len).htons
    result.setLen(result.len + 2)
    copyMem(result[result.len - 2].addr, l.addr, 2)
  else:
    result.add 127.char
    var l = cast[uint32](data.len).htonl
    result.setLen(result.len + 8)
    copyMem(result[result.len - 4].addr, l.addr, 4)

  result.add data # This may be an expensive copy

  assert result.len == frameLen

# proc popWsMsg(
#   server: HttpServer,
#   clientSocket: SocketHandle,
#   socketState: SocketState
# ): WsMsg {.raises: [].} =
#   ## Pops the completed WsMsg from the socket and resets the parse state.
#   result = WsMsg()
#   # result.kind =
#   result.data = move socketState.msgState.buffer
#   result.data.setLen(socketState.msgState.msgLen)
#   socketState.msgState = IncomingWsMsgState()

proc sendPongMsg(
  server: HttpServer,
  clientSocket: SocketHandle,
  socketState: SocketState
) {.raises: [IOSelectorsException].} =
  let outgoingPayload = OutgoingPayloadState()
  outgoingPayload.buffer = encodeFrame(0xA, "")
  socketState.outgoingPayloads.addLast(outgoingPayload)
  server.selector.updateHandle2(clientSocket, {Read, Write})

proc sendCloseMsg(
  server: HttpServer,
  clientSocket: SocketHandle,
  socketState: SocketState,
  closeConnection: bool
) {.raises: [IOSelectorsException].} =
  let outgoingPayload = OutgoingPayloadState()
  outgoingPayload.buffer = encodeFrame(0x8, "")
  outgoingPayload.closeConnection = closeConnection
  socketState.outgoingPayloads.addLast(outgoingPayload)
  socketState.closeFrameSent = true
  server.selector.updateHandle2(clientSocket, {Read, Write})

proc afterRecvWebSocket(
  server: HttpServer,
  clientSocket: SocketHandle,
  socketState: SocketState
): bool {.raises: [IOSelectorsException].} =
  # Try to parse entire frames out of the receive buffer
  while true:
    if socketState.bytesReceived < 2:
      return false # Need to receive more bytes

    let
      b0 = socketState.recvBuffer[0].uint8
      b1 = socketState.recvBuffer[1].uint8
      fin = (b0 and 0b10000000) != 0
      rsv1 = b0 and 0b01000000
      rsv2 = b0 and 0b00100000
      rsv3 = b0 and 0b00010000
      opcode = b0 and 0b00001111

    if rsv1 != 0 or rsv2 != 0 or rsv3 != 0:
      return true # Per spec this must fail, close the connection

    # Masking bit should be set
    if (b1 and 0b10000000) == 0:
      return true # Per spec, close the connection

    if opcode == 0 and socketState.msgState.opcode == 0:
      # Per spec, the first frame must have an opcode > 0
      return true # Close the connection

    if socketState.msgState.opcode != 0 and opcode != 0:
      # Per spec, if we have buffered fragments the opcode must be 0
      return true # Close the connection

    var pos = 2

    var payloadLen = (b1 and 0b01111111).int
    if payloadLen <= 125:
      discard
    elif payloadLen == 126:
      if socketState.bytesReceived < 4:
        return false # Need to receive more bytes
      var l: uint16
      copyMem(l.addr, socketState.recvBuffer[pos].addr, 2)
      payloadLen = l.htons.int
      pos += 2
    else:
      if socketState.bytesReceived < 10:
        return false # Need to receive more bytes
      var l: uint32
      copyMem(l.addr, socketState.recvBuffer[pos + 4].addr, 4)
      payloadLen = l.htonl.int
      pos += 8

    if socketState.msgState.msgLen + payloadLen > server.maxBodyLen:
      return true # Message is too large, close the connection

    if socketState.bytesReceived < pos + 4:
      return false # Need to receive more bytes

    var mask: array[4, uint8]
    copyMem(mask.addr, socketState.recvBuffer[pos].addr, 4)

    pos += 4

    if socketState.bytesReceived < pos + payloadLen:
      return false # Need to receive more bytes

    # Unmask the payload
    for i in 0 ..< payloadLen:
      let j = i mod 4
      socketState.recvBuffer[pos + i] =
        (socketState.recvBuffer[pos + i].uint8 xor mask[j]).char

    if socketState.msgState.opcode == 0:
      # This is the first fragment
      socketState.msgState.opcode = opcode

    # Make room in the message buffer for this fragment
    let newMsgLen = socketState.msgState.msgLen + payloadLen
    if socketState.msgState.buffer.len < newMsgLen:
      let newBufferLen = max(socketState.msgState.buffer.len * 2, newMsgLen)
      socketState.msgState.buffer.setLen(newBufferLen)

    if payloadLen > 0:
      # Copy the fragment into the message buffer
      copyMem(
        socketState.msgState.buffer[socketState.msgState.msgLen].addr,
        socketState.recvBuffer[pos].addr,
        payloadLen
      )
      socketState.msgState.msgLen += payloadLen

    # Remove this frame from the receive buffer
    let frameLen = pos + payloadLen
    if socketState.bytesReceived == frameLen:
      socketState.bytesReceived = 0
    else:
      copyMem(
        socketState.recvBuffer[0].addr,
        socketState.recvBuffer[frameLen].addr,
        socketState.bytesReceived - frameLen
      )
      socketState.bytesReceived -= frameLen

    if fin:
      if socketState.msgState.opcode == 0:
        return true # Invalid frame, close the connection

      # We have a full message

      case opcode:
      of 0x1: # Text
        discard
      of 0x2: # Binary
        discard
      of 0x8: # Close
        # If we already sent a close, just close the connection
        if socketState.closeFrameSent:
          return true # Close the connection
        # Otherwise send a Close in response then close the connection
        server.sendCloseMsg(clientSocket, socketState, true)
      of 0x9: # Ping
        server.sendPongMsg(clientSocket, socketState)
      of 0xA: # Pong
        discard
      else:
        # Drop invalid opcodes
        # TODO: log?
        discard

proc encode(response: var HttpResponse): string {.raises: [], gcsafe.} =
  let statusLine = "HTTP/1.1 " & $response.statusCode & "\r\n"

  var totalLen = statusLine.len
  for (k, v) in response.headers:
    # k + ": " + v + "\r\n"
    totalLen += k.len + 2 + v.len + 2
  # "\r\n" + response.body
  totalLen += 2 + response.body.len

  result = newStringOfCap(totalLen)
  result.add statusLine

  for (k, v) in response.headers:
    result.add k & ": " & v & "\r\n"

  result.add "\r\n"
  result.add response.body # This may be an expensive copy

  assert result.len == totalLen

proc popRequest(
  server: HttpServer,
  clientSocket: SocketHandle,
  socketState: SocketState
): HttpRequest {.raises: [].} =
  ## Pops the completed HttpRequest from the socket and resets the parse state.
  result = HttpRequest()
  result.server = cast[ptr HttpServerObj](server)
  result.clientSocket = clientSocket
  result.httpVersion = socketState.requestState.httpVersion
  result.httpMethod = move socketState.requestState.httpMethod
  result.uri = move socketState.requestState.uri
  result.headers = move socketState.requestState.headers
  result.body = move socketState.requestState.body
  result.body.setLen(socketState.requestState.contentLength)
  socketState.requestState = IncomingRequestState()

proc afterRecvHttp(
  server: HttpServer,
  clientSocket: SocketHandle,
  socketState: SocketState
): bool {.raises: [].} =
  # Have we completed parsing the headers?
  if not socketState.requestState.headersParsed:
    # Not done with headers yet, look for the end of the headers
    let headersEnd = socketState.recvBuffer.find(
      "\r\n\r\n",
      0,
      min(socketState.bytesReceived, server.maxHeadersLen) - 1 # Inclusive
    )
    if headersEnd < 0: # Headers end not found
      if socketState.bytesReceived > server.maxHeadersLen:
        return true # Headers too long or malformed, close the connection
      return false # Try again after receiving more bytes

    # We have the headers, now to parse them
    var
      headerLines: seq[string]
      nextLineStart: int
    while true:
      let lineEnd = socketState.recvBuffer.find(
        "\r\n",
        nextLineStart,
        headersEnd
      )
      if lineEnd == -1:
        var line = socketState.recvBuffer[nextLineStart ..< headersEnd].strip()
        headerLines.add(move line)
        break
      else:
        headerLines.add(socketState.recvBuffer[nextLineStart ..< lineEnd].strip())
        nextLineStart = lineEnd + 2

    let
      requestLine = headerLines[0]
      requestLineParts = requestLine.split(" ")
    if requestLineParts.len != 3:
      return true # Malformed request line, close the connection

    socketState.requestState.httpMethod = requestLineParts[0]
    socketState.requestState.uri = requestLineParts[1]

    if requestLineParts[2] == "HTTP/1.0":
      socketState.requestState.httpVersion = Http10
    elif requestLineParts[2] == "HTTP/1.1":
      socketState.requestState.httpVersion = Http11
    else:
      return true # Unsupported HTTP version, close the connection

    for i in 1 ..< headerLines.len:
      let parts = headerLines[i].split(": ")
      if parts.len == 2:
        socketState.requestState.headers.add((parts[0], parts[1]))
      else:
        socketState.requestState.headers.add((headerLines[i], ""))

    socketState.requestState.chunked =
      socketState.requestState.headers.headerContainsToken(
        "Transfer-Encoding", "chunked"
      )

    # If this is a chunked request ignore any Content-Length headers
    if not socketState.requestState.chunked:
      var foundContentLength: bool
      for (k, v) in socketState.requestState.headers:
        if cmpIgnoreCase(k, "Content-Length") == 0:
          if foundContentLength:
            # This is a second Content-Length header, not valid
            return true # Close the connection
          foundContentLength = true
          try:
            socketState.requestState.contentLength = parseInt(v)
          except:
            return true # Parsing Content-Length failed, close the connection

      if socketState.requestState.contentLength < 0:
        return true # Invalid Content-Length, close the connection

    # Remove the headers from the receive buffer
    let bodyStart = headersEnd + 4
    if socketState.bytesReceived == bodyStart:
      socketState.bytesReceived = 0
    else:
      copyMem(
        socketState.recvBuffer[0].addr,
        socketState.recvBuffer[bodyStart].addr,
        socketState.bytesReceived - bodyStart
      )
      socketState.bytesReceived -= bodyStart

    # One of three possible states for request body:
    # 1) We received a Content-Length header, so we know the content length
    # 2) We received a Transfer-Encoding: chunked header
    # 3) Neither, so we assume a content length of 0

    # Mark that headers have been parsed, must end this block
    socketState.requestState.headersParsed = true

  # Headers have been parsed, now for the body

  if socketState.requestState.chunked: # Chunked request
    # Process as many chunks as we have
    while true:
      if socketState.bytesReceived < 3:
        return false # Need to receive more bytes

      # Look for the end of the chunk length
      let chunkLenEnd = socketState.recvBuffer.find(
        "\r\n",
        0,
        min(socketState.bytesReceived - 1, 19) # Inclusive with a reasonable max
      )
      if chunkLenEnd < 0: # Chunk length end not found
        if socketState.bytesReceived > 19:
          return true # We should have found it, close the connection
        return false # Try again after receiving more bytes

      var chunkLen: int
      try:
        discard parseHex(
          socketState.recvBuffer,
          chunkLen,
          0,
          chunkLenEnd
        )
      except:
        return true # Parsing chunk length failed, close the connection

      if socketState.requestState.contentLength + chunkLen > server.maxBodyLen:
        return true # Body is too large, close the connection

      let chunkStart = chunkLenEnd + 2
      if socketState.bytesReceived < chunkStart + chunkLen + 2:
        return false # Need to receive more bytes

      # Make room in the body buffer for this chunk
      let newContentLength = socketState.requestState.contentLength + chunkLen
      if socketState.requestState.body.len < newContentLength:
        let newLen = max(socketState.requestState.body.len * 2, newContentLength)
        socketState.requestState.body.setLen(newLen)

      copyMem(
        socketState.requestState.body[socketState.requestState.contentLength].addr,
        socketState.recvBuffer[chunkStart].addr,
        chunkLen
      )

      socketState.requestState.contentLength += chunkLen

      # Remove this chunk from the receive buffer
      let
        nextChunkStart = chunkLenEnd + 2 + chunkLen + 2
        bytesRemaining = socketState.bytesReceived - nextChunkStart
      copyMem(
        socketState.recvBuffer[0].addr,
        socketState.recvBuffer[nextChunkStart].addr,
        bytesRemaining
      )
      socketState.bytesReceived = bytesRemaining

      if chunkLen == 0:
        var request = server.popRequest(clientSocket, socketState)
        acquire(server.requestQueueLock)
        server.requestQueue.addLast(move request)
        release(server.requestQueueLock)
        signal(server.requestQueueCond)
        return false
  else:
    if socketState.requestState.contentLength > server.maxBodyLen:
      return true # Body is too large, close the connection

    if socketState.bytesReceived < socketState.requestState.contentLength:
      return false # Need to receive more bytes

    # We have the entire request body

    # If this request has a body, fill it
    if socketState.requestState.contentLength > 0:
      socketState.requestState.body.setLen(socketState.requestState.contentLength)
      copyMem(
        socketState.requestState.body[0].addr,
        socketState.recvBuffer[0].addr,
        socketState.requestState.contentLength
      )

    # Remove this request from the receive buffer
    let bytesRemaining =
      socketState.bytesReceived - socketState.requestState.contentLength
    copyMem(
      socketState.recvBuffer[0].addr,
      socketState.recvBuffer[socketState.requestState.contentLength].addr,
      bytesRemaining
    )
    socketState.bytesReceived = bytesRemaining

    var request = server.popRequest(clientSocket, socketState)
    acquire(server.requestQueueLock)
    server.requestQueue.addLast(move request)
    release(server.requestQueueLock)
    signal(server.requestQueueCond)

proc afterRecv(
  server: HttpServer,
  clientSocket: SocketHandle,
  socketState: SocketState
): bool {.raises: [IOSelectorsException].} =
  # Have we upgraded this connection to a websocket?
  # If not, treat incoming bytes as part of HTTP requests.
  if socketState.upgradedToWebSocket:
    server.afterRecvWebSocket(clientSocket, socketState)
  else:
    server.afterRecvHttp(clientSocket, socketState)

proc afterSend(
  server: HttpServer,
  clientSocket: SocketHandle,
  socketState: SocketState
): bool {.raises: [IOSelectorsException].} =
  let outgoingPayload = socketState.outgoingPayloads.peekFirst()
  if outgoingPayload.bytesSent == outgoingPayload.buffer.len:
    socketState.outgoingPayloads.shrink(1)
    if outgoingPayload.closeConnection:
      return true
  if socketState.outgoingPayloads.len == 0:
    server.selector.updateHandle2(clientSocket, {Read})

proc loopForever(
  server: HttpServer,
  port: Port
) {.raises: [OSError, IOSelectorsException].} =
  var
    readyKeys: array[maxEventsPerSelectLoop, ReadyKey]
    receivedFrom, sentTo, needClosing: seq[SocketHandle]
  while true:
    receivedFrom.setLen(0)
    sentTo.setLen(0)
    needClosing.setLen(0)
    let readyCount = server.selector.selectInto(-1, readyKeys)
    for i in 0 ..< readyCount:
      let readyKey = readyKeys[i]

      # echo "Socket ready: ", readyKey.fd, " ", readyKey.events

      if User in readyKey.events:
        # This must be the responseReady event
        acquire(server.responseQueueLock)
        var encodedResponse = server.responseQueue.popFirst()
        release(server.responseQueueLock)

        if encodedResponse.clientSocket in server.selector:
          let socketState = server.selector.getData(encodedResponse.clientSocket)

          if encodedResponse.websocketUpgrade:
            socketState.upgradedToWebSocket = true
            if socketState.bytesReceived > 0:
              # Why have we received bytes when we are upgrading the connection?
              needClosing.add(readyKey.fd.SocketHandle)
              continue

          let outgoingPayload = OutgoingPayloadState()
          outgoingPayload.closeConnection = encodedResponse.closeConnection
          outgoingPayload.buffer = move encodedResponse.buffer
          socketState.outgoingPayloads.addLast(outgoingPayload)
          server.selector.updateHandle2(
            encodedResponse.clientSocket,
            {Read, Write}
          )
        continue

      if readyKey.fd == server.socket.int:
        if Read in readyKey.events:
          let (clientSocket, _) = server.socket.accept()
          if clientSocket == osInvalidSocket:
            continue

          clientSocket.setBlocking(false)
          server.clientSockets.incl(clientSocket)

          let socketState = SocketState()
          socketState.recvBuffer.setLen(initialRecvBufferLen)
          server.selector.registerHandle(clientSocket, {Read}, socketState)
      else:
        if Error in readyKey.events:
          needClosing.add(readyKey.fd.SocketHandle)
          continue

        let socketState = server.selector.getData(readyKey.fd)

        if Read in readyKey.events:
          # Expand the buffer if it is full
          if socketState.bytesReceived == socketState.recvBuffer.len:
            socketState.recvBuffer.setLen(socketState.recvBuffer.len * 2)

          let bytesReceived = readyKey.fd.SocketHandle.recv(
            socketState.recvBuffer[socketState.bytesReceived].addr,
            socketState.recvBuffer.len - socketState.bytesReceived,
            0
          )
          if bytesReceived > 0:
            socketState.bytesReceived += bytesReceived
            receivedFrom.add(readyKey.fd.SocketHandle)
          else:
            needClosing.add(readyKey.fd.SocketHandle)
            continue

        if Write in readyKey.events:
          let
            outgoingPayload = socketState.outgoingPayloads.peekFirst()
            bytesSent = readyKey.fd.SocketHandle.send(
              outgoingPayload.buffer[outgoingPayload.bytesSent].addr,
              outgoingPayload.buffer.len - outgoingPayload.bytesSent,
              0
            )
          if bytesSent > 0:
            outgoingPayload.bytesSent += bytesSent
            sentTo.add(readyKey.fd.SocketHandle)
          else:
            needClosing.add(readyKey.fd.SocketHandle)
            continue

    for clientSocket in receivedFrom:
      if clientSocket in needClosing:
        continue
      let
        socketState = server.selector.getData(clientSocket)
        needsClosing = server.afterRecv(clientSocket, socketState)
      if needsClosing:
        needClosing.add(clientSocket)

    for clientSocket in sentTo:
      if clientSocket in needClosing:
        continue
      let
        socketState = server.selector.getData(clientSocket)
        needsClosing = server.afterSend(clientSocket, socketState)
      if needsClosing:
        needClosing.add(clientSocket)

    for clientSocket in needClosing:
      try:
        server.selector.unregister(clientSocket)
      except:
        # Leaks SocketState for this socket
        # Raise as a serve() exception
        raise cast[ref IOSelectorsException](getCurrentException())
      clientSocket.close()
      server.clientSockets.excl(clientSocket)

proc serve*(
  server: HttpServer,
  port: Port
) {.raises: [HttpServerError].} =
  if server.socket.int != 0:
    raise newException(HttpServerError, "Server already has a socket")

  try:
    server.socket = createNativeSocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, false)
    if server.socket == osInvalidSocket:
      raiseOSError(osLastError())

    server.socket.setBlocking(false)
    server.socket.setSockOptInt(SOL_SOCKET, SO_REUSEADDR, 1)

    let ai = getAddrInfo(
      "0.0.0.0",
      port,
      AF_INET,
      SOCK_STREAM,
      IPPROTO_TCP
    )
    try:
      if bindAddr(server.socket, ai.ai_addr, ai.ai_addrlen.SockLen) < 0:
        raiseOSError(osLastError())
    finally:
      freeAddrInfo(ai)

    if server.socket.listen(listenBacklogLen) < 0:
      raiseOSError(osLastError())

    server.selector = newSelector[SocketState]()
    server.selector.registerEvent(server.responseReady, nil)
    server.selector.registerHandle(server.socket, {Read}, nil)
  except:
    if server.selector != nil:
      try:
        server.selector.close()
      except:
        discard # Ignore
    if server.socket.int != 0:
      server.socket.close()
    raise currentExceptionAsHttpServerError()

  try:
    server.loopForever(port)
  except:
    try:
      server.selector.close()
    except:
      discard # Ignore
    for clientSocket in server.clientSockets:
      clientSocket.close()
    server.socket.close()
    raise currentExceptionAsHttpServerError()

proc workerProc(server: ptr HttpServerObj) {.raises: [].} =
  while true:
    acquire(server.requestQueueLock)

    while server.requestQueue.len == 0 and server.running:
      wait(server.requestQueueCond, server.requestQueueLock)

    if not server.running:
      release(server.requestQueueLock)
      return

    var request = server.requestQueue.popFirst()

    release(server.requestQueueLock)

    let
      server = request.server
      clientSocket = request.clientSocket
      httpVersion = request.httpVersion

    var encodedResponse = EncodedHttpResponse()
    encodedResponse.clientSocket = clientSocket
    encodedResponse.closeConnection = httpVersion == Http10 # Default behavior

    # Override default behavior based on Connection header
    if request.headers.headerContainsToken("Connection", "close"):
      encodedResponse.closeConnection = true
    elif request.headers.headerContainsToken("Connection", "keep-alive"):
      encodedResponse.closeConnection = false

    var response: HttpResponse
    try:
      {.gcsafe.}: # lol
        # Move request to avoid looking at it later, may be modified by handler
        server.handler(move request, response)
    except:
      # TODO: log?
      response = HttpResponse()
      response.statusCode = 500

    # If we are not already going to close the connection, check if we should
    if not encodedResponse.closeConnection:
      encodedResponse.closeConnection = response.headers.headerContainsToken(
        "Connection", "close"
      )

    if encodedResponse.closeConnection:
      response.headers["Connection"] = "close"
    elif httpVersion == Http10 or "Connection" notin response.headers:
      response.headers["Connection"] = "keep-alive"

    response.headers["Content-Length"] = $response.body.len

    encodedResponse.buffer = response.encode()

    encodedResponse.websocketUpgrade = response.websocketUpgrade

    acquire(server.responseQueueLock)
    server.responseQueue.addLast(move encodedResponse)
    release(server.responseQueueLock)

    try:
      server.responseReady.trigger()
    except:
      echo "UHH????", getCurrentExceptionMsg()



proc newHttpServer*(
  handler: HttpHandler,
  websocketHander: WebSocketHandler = nil,
  workerThreads = max(countProcessors() - 1, 1),
  maxHeadersLen = 8 * 1024, # 8 KB
  maxBodyLen = 1024 * 1024 # 1 MB
): HttpServer {.raises: [HttpServerError].} =
  result = HttpServer()
  result.handler = handler
  result.websocketHander = websocketHander
  result.maxHeadersLen = maxHeadersLen
  result.maxBodyLen = maxBodyLen
  result.running = true
  initLock(result.requestQueueLock)
  initCond(result.requestQueueCond)
  initLock(result.responseQueueLock)
  result.workerThreads.setLen(workerThreads)
  result.nextWebSocketId = 1

  try:
    result.responseReady = newSelectEvent()

    # Start the worker threads
    for workerThead in result.workerThreads.mitems:
      createThread(workerThead, workerProc, cast[ptr HttpServerObj](result))
  except:
    acquire(result.requestQueueLock)
    result.running = false
    release(result.requestQueueLock)
    broadcast(result.requestQueueCond)
    joinThreads(result.workerThreads)
    deinitLock(result.requestQueueLock)
    deinitCond(result.requestQueueCond)
    deinitLock(result.responseQueueLock)
    try:
      result.responseReady.close()
    except:
      discard # Ignore
    raise currentExceptionAsHttpServerError()
