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

  HttpHandler* = proc(request: HttpRequest, response: var HttpResponse) {.gcsafe.}

  WebSocketHandler* = proc(websocket: WebSocket)

  HttpServer* = ref HttpServerObj

  HttpServerObj = object
    handler: HttpHandler
    websocketHander: WebSocketHandler
    maxHeadersLen, maxBodyLen: int
    workerThreads: seq[Thread[ptr HttpServerObj]]
    running: bool
    socket: SocketHandle
    selector: Selector[HandleData]
    responseQueued, sendQueued: SelectEvent
    clientSockets: HashSet[SocketHandle]
    requestQueue: Deque[HttpRequest]
    requestQueueLock: Lock
    requestQueueCond: Cond
    responseQueue: Deque[EncodedHttpResponse]
    responseQueueLock: Lock
    sendQueue: Deque[EncodedFrame]
    sendQueueLock: Lock

  HandleKind = enum
    ServerSocket, ClientSocket, ResponseQueuedEvent, SendQueuedEvent

  HandleData = ref object
    handleKind: HandleKind
    recvBuffer: string
    bytesReceived: int
    requestState: IncomingRequestState
    msgState: IncomingWsMsgState
    outgoingBuffers: Deque[OutgoingBuffer]
    upgradedToWebSocket, closeFrameQueued, closeFrameSent: bool
    sendsWaitingForUpgrade: seq[EncodedFrame]

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

  OutgoingBuffer = ref object
    closeConnection, isCloseFrame: bool
    buffer1, buffer2: string
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
    websocketUpgradeCalled: bool

  HttpResponse* = object
    statusCode*: int
    headers*: HttpHeaders
    body*: string

  EncodedHttpResponse = ref object
    clientSocket: SocketHandle
    isWebSocketUpgrade, closeConnection: bool
    buffer1, buffer2: string

  EncodedFrame = ref object
    clientSocket: SocketHandle
    isCloseFrame: bool
    buffer1, buffer2: string

  WebSocket* = object
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
  selector: Selector[HandleData],
  socket: SocketHandle,
  events: set[Event]
) {.raises: [IOSelectorsException].} =
  try:
    selector.updateHandle(socket, events)
  except ValueError: # Why ValueError?
    raise newException(IOSelectorsException, getCurrentExceptionMsg())

proc trigger2(
  event: SelectEvent
) {.raises: [].} =
  try:
    event.trigger()
  except:
    # TODO: EAGAIN vs other
    echo "Triggering event failed"

proc encodeFrameHeader(
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

proc send*(
  websocket: WebSocket,
  data: sink string,
  kind = TextMsg,
) {.raises: [], gcsafe.} =
  let encodedFrame = EncodedFrame()
  encodedFrame.clientSocket = websocket.clientSocket

  case kind:
  of TextMsg:
    encodedFrame.buffer1 = encodeFrameHeader(0x1, data.len)
  of BinaryMsg:
    encodedFrame.buffer1 = encodeFrameHeader(0x2, data.len)

  encodedFrame.buffer2 = move data

  acquire(websocket.server.sendQueueLock)
  websocket.server.sendQueue.addLast(encodedFrame)
  release(websocket.server.sendQueueLock)

  websocket.server.sendQueued.trigger2()

proc close*(websocket: WebSocket) {.raises: [], gcsafe.} =
  let encodedFrame = EncodedFrame()
  encodedFrame.clientSocket = websocket.clientSocket
  encodedFrame.buffer1 = encodeFrameHeader(0x8, 0)
  encodedFrame.isCloseFrame = true

  acquire(websocket.server.sendQueueLock)
  websocket.server.sendQueue.addLast(encodedFrame)
  release(websocket.server.sendQueueLock)

  websocket.server.sendQueued.trigger2()

proc websocketUpgrade*(
  request: HttpRequest,
  response: var HttpResponse
): WebSocket {.raises: [HttpServerError], gcsafe.} =
  if request.websocketUpgradeCalled:
    raise newException(
      HttpServerError,
      "This request has already been upgraded"
    )

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

  # Looks good to upgrade

  request.websocketUpgradeCalled = true

  result.server = request.server
  result.clientSocket = request.clientSocket

  let hash =
    secureHash(websocketKey & "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").Sha1Digest

  response.statusCode = 101
  response.headers["Connection"] = "upgrade"
  response.headers["Upgrade"] = "websocket"
  response.headers["Sec-WebSocket-Accept"] = base64.encode(hash)

proc popWsMsg(handleData: HandleData): WsMsg {.raises: [].} =
  ## Pops the completed WsMsg from the socket and resets the parse state.
  result = WsMsg()
  result.data = move handleData.msgState.buffer
  result.data.setLen(handleData.msgState.msgLen)
  handleData.msgState = IncomingWsMsgState()

proc sendPongMsg(
  server: HttpServer,
  clientSocket: SocketHandle,
  handleData: HandleData
) {.raises: [IOSelectorsException].} =
  let outgoingBuffer = OutgoingBuffer()
  outgoingBuffer.buffer1 = encodeFrameHeader(0xA, 0)
  handleData.outgoingBuffers.addLast(outgoingBuffer)
  server.selector.updateHandle2(clientSocket, {Read, Write})

proc sendCloseMsg(
  server: HttpServer,
  clientSocket: SocketHandle,
  handleData: HandleData,
  closeConnection: bool
) {.raises: [IOSelectorsException].} =
  let outgoingBuffer = OutgoingBuffer()
  outgoingBuffer.buffer1 = encodeFrameHeader(0x8, 0)
  outgoingBuffer.isCloseFrame = true
  outgoingBuffer.closeConnection = closeConnection
  handleData.outgoingBuffers.addLast(outgoingBuffer)
  handleData.closeFrameQueued = true
  server.selector.updateHandle2(clientSocket, {Read, Write})

proc afterRecvWebSocket(
  server: HttpServer,
  clientSocket: SocketHandle,
  handleData: HandleData
): bool {.raises: [IOSelectorsException].} =
  # Try to parse entire frames out of the receive buffer
  while true:
    if handleData.bytesReceived < 2:
      return false # Need to receive more bytes

    let
      b0 = handleData.recvBuffer[0].uint8
      b1 = handleData.recvBuffer[1].uint8
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

    if opcode == 0 and handleData.msgState.opcode == 0:
      # Per spec, the first frame must have an opcode > 0
      return true # Close the connection

    if handleData.msgState.opcode != 0 and opcode != 0:
      # Per spec, if we have buffered fragments the opcode must be 0
      return true # Close the connection

    var pos = 2

    var payloadLen = (b1 and 0b01111111).int
    if payloadLen <= 125:
      discard
    elif payloadLen == 126:
      if handleData.bytesReceived < 4:
        return false # Need to receive more bytes
      var l: uint16
      copyMem(l.addr, handleData.recvBuffer[pos].addr, 2)
      payloadLen = l.htons.int
      pos += 2
    else:
      if handleData.bytesReceived < 10:
        return false # Need to receive more bytes
      var l: uint32
      copyMem(l.addr, handleData.recvBuffer[pos + 4].addr, 4)
      payloadLen = l.htonl.int
      pos += 8

    if handleData.msgState.msgLen + payloadLen > server.maxBodyLen:
      return true # Message is too large, close the connection

    if handleData.bytesReceived < pos + 4:
      return false # Need to receive more bytes

    var mask: array[4, uint8]
    copyMem(mask.addr, handleData.recvBuffer[pos].addr, 4)

    pos += 4

    if handleData.bytesReceived < pos + payloadLen:
      return false # Need to receive more bytes

    # Unmask the payload
    for i in 0 ..< payloadLen:
      let j = i mod 4
      handleData.recvBuffer[pos + i] =
        (handleData.recvBuffer[pos + i].uint8 xor mask[j]).char

    if handleData.msgState.opcode == 0:
      # This is the first fragment
      handleData.msgState.opcode = opcode

    # Make room in the message buffer for this fragment
    let newMsgLen = handleData.msgState.msgLen + payloadLen
    if handleData.msgState.buffer.len < newMsgLen:
      let newBufferLen = max(handleData.msgState.buffer.len * 2, newMsgLen)
      handleData.msgState.buffer.setLen(newBufferLen)

    if payloadLen > 0:
      # Copy the fragment into the message buffer
      copyMem(
        handleData.msgState.buffer[handleData.msgState.msgLen].addr,
        handleData.recvBuffer[pos].addr,
        payloadLen
      )
      handleData.msgState.msgLen += payloadLen

    # Remove this frame from the receive buffer
    let frameLen = pos + payloadLen
    if handleData.bytesReceived == frameLen:
      handleData.bytesReceived = 0
    else:
      copyMem(
        handleData.recvBuffer[0].addr,
        handleData.recvBuffer[frameLen].addr,
        handleData.bytesReceived - frameLen
      )
      handleData.bytesReceived -= frameLen

    if fin:
      if handleData.msgState.opcode == 0:
        return true # Invalid frame, close the connection

      # We have a full message
      let msg = handleData.popWsMsg()

      case opcode:
      of 0x1: # Text
        msg.kind = TextMsg
      of 0x2: # Binary
        msg.kind = BinaryMsg
      of 0x8: # Close
        # If we already queued a close, just close the connection
        # This is not quite perfect
        if handleData.closeFrameQueued:
          return true # Close the connection
        # Otherwise send a Close in response then close the connection
        if not handleData.closeFrameQueued:
          server.sendCloseMsg(clientSocket, handleData, true)
        continue
      of 0x9: # Ping
        server.sendPongMsg(clientSocket, handleData)
        continue
      of 0xA: # Pong
        continue
      else:
        return true # Invalid opcode, close the connection

      # The message must be a text or binary message

      discard



proc encodeHeaders(response: var HttpResponse): string {.raises: [], gcsafe.} =
  let statusLine = "HTTP/1.1 " & $response.statusCode & "\r\n"

  var headersLen = statusLine.len
  for (k, v) in response.headers:
    # k + ": " + v + "\r\n"
    headersLen += k.len + 2 + v.len + 2
  # "\r\n"
  headersLen += 2

  result = newStringOfCap(headersLen)
  result.add statusLine

  for (k, v) in response.headers:
    result.add k & ": " & v & "\r\n"

  result.add "\r\n"

proc popRequest(
  server: HttpServer,
  clientSocket: SocketHandle,
  handleData: HandleData
): HttpRequest {.raises: [].} =
  ## Pops the completed HttpRequest from the socket and resets the parse state.
  result = HttpRequest()
  result.server = cast[ptr HttpServerObj](server)
  result.clientSocket = clientSocket
  result.httpVersion = handleData.requestState.httpVersion
  result.httpMethod = move handleData.requestState.httpMethod
  result.uri = move handleData.requestState.uri
  result.headers = move handleData.requestState.headers
  result.body = move handleData.requestState.body
  result.body.setLen(handleData.requestState.contentLength)
  handleData.requestState = IncomingRequestState()

proc afterRecvHttp(
  server: HttpServer,
  clientSocket: SocketHandle,
  handleData: HandleData
): bool {.raises: [].} =
  # Have we completed parsing the headers?
  if not handleData.requestState.headersParsed:
    # Not done with headers yet, look for the end of the headers
    let headersEnd = handleData.recvBuffer.find(
      "\r\n\r\n",
      0,
      min(handleData.bytesReceived, server.maxHeadersLen) - 1 # Inclusive
    )
    if headersEnd < 0: # Headers end not found
      if handleData.bytesReceived > server.maxHeadersLen:
        return true # Headers too long or malformed, close the connection
      return false # Try again after receiving more bytes

    # We have the headers, now to parse them
    var
      headerLines: seq[string]
      nextLineStart: int
    while true:
      let lineEnd = handleData.recvBuffer.find(
        "\r\n",
        nextLineStart,
        headersEnd
      )
      if lineEnd == -1:
        var line = handleData.recvBuffer[nextLineStart ..< headersEnd].strip()
        headerLines.add(move line)
        break
      else:
        headerLines.add(handleData.recvBuffer[nextLineStart ..< lineEnd].strip())
        nextLineStart = lineEnd + 2

    let
      requestLine = headerLines[0]
      requestLineParts = requestLine.split(" ")
    if requestLineParts.len != 3:
      return true # Malformed request line, close the connection

    handleData.requestState.httpMethod = requestLineParts[0]
    handleData.requestState.uri = requestLineParts[1]

    if requestLineParts[2] == "HTTP/1.0":
      handleData.requestState.httpVersion = Http10
    elif requestLineParts[2] == "HTTP/1.1":
      handleData.requestState.httpVersion = Http11
    else:
      return true # Unsupported HTTP version, close the connection

    for i in 1 ..< headerLines.len:
      let parts = headerLines[i].split(": ")
      if parts.len == 2:
        handleData.requestState.headers.add((parts[0], parts[1]))
      else:
        handleData.requestState.headers.add((headerLines[i], ""))

    handleData.requestState.chunked =
      handleData.requestState.headers.headerContainsToken(
        "Transfer-Encoding", "chunked"
      )

    # If this is a chunked request ignore any Content-Length headers
    if not handleData.requestState.chunked:
      var foundContentLength: bool
      for (k, v) in handleData.requestState.headers:
        if cmpIgnoreCase(k, "Content-Length") == 0:
          if foundContentLength:
            # This is a second Content-Length header, not valid
            return true # Close the connection
          foundContentLength = true
          try:
            handleData.requestState.contentLength = parseInt(v)
          except:
            return true # Parsing Content-Length failed, close the connection

      if handleData.requestState.contentLength < 0:
        return true # Invalid Content-Length, close the connection

    # Remove the headers from the receive buffer
    let bodyStart = headersEnd + 4
    if handleData.bytesReceived == bodyStart:
      handleData.bytesReceived = 0
    else:
      copyMem(
        handleData.recvBuffer[0].addr,
        handleData.recvBuffer[bodyStart].addr,
        handleData.bytesReceived - bodyStart
      )
      handleData.bytesReceived -= bodyStart

    # One of three possible states for request body:
    # 1) We received a Content-Length header, so we know the content length
    # 2) We received a Transfer-Encoding: chunked header
    # 3) Neither, so we assume a content length of 0

    # Mark that headers have been parsed, must end this block
    handleData.requestState.headersParsed = true

  # Headers have been parsed, now for the body

  if handleData.requestState.chunked: # Chunked request
    # Process as many chunks as we have
    while true:
      if handleData.bytesReceived < 3:
        return false # Need to receive more bytes

      # Look for the end of the chunk length
      let chunkLenEnd = handleData.recvBuffer.find(
        "\r\n",
        0,
        min(handleData.bytesReceived - 1, 19) # Inclusive with a reasonable max
      )
      if chunkLenEnd < 0: # Chunk length end not found
        if handleData.bytesReceived > 19:
          return true # We should have found it, close the connection
        return false # Try again after receiving more bytes

      var chunkLen: int
      try:
        discard parseHex(
          handleData.recvBuffer,
          chunkLen,
          0,
          chunkLenEnd
        )
      except:
        return true # Parsing chunk length failed, close the connection

      if handleData.requestState.contentLength + chunkLen > server.maxBodyLen:
        return true # Body is too large, close the connection

      let chunkStart = chunkLenEnd + 2
      if handleData.bytesReceived < chunkStart + chunkLen + 2:
        return false # Need to receive more bytes

      # Make room in the body buffer for this chunk
      let newContentLength = handleData.requestState.contentLength + chunkLen
      if handleData.requestState.body.len < newContentLength:
        let newLen = max(handleData.requestState.body.len * 2, newContentLength)
        handleData.requestState.body.setLen(newLen)

      copyMem(
        handleData.requestState.body[handleData.requestState.contentLength].addr,
        handleData.recvBuffer[chunkStart].addr,
        chunkLen
      )

      handleData.requestState.contentLength += chunkLen

      # Remove this chunk from the receive buffer
      let
        nextChunkStart = chunkLenEnd + 2 + chunkLen + 2
        bytesRemaining = handleData.bytesReceived - nextChunkStart
      copyMem(
        handleData.recvBuffer[0].addr,
        handleData.recvBuffer[nextChunkStart].addr,
        bytesRemaining
      )
      handleData.bytesReceived = bytesRemaining

      if chunkLen == 0:
        var request = server.popRequest(clientSocket, handleData)
        acquire(server.requestQueueLock)
        server.requestQueue.addLast(move request)
        release(server.requestQueueLock)
        signal(server.requestQueueCond)
        return false
  else:
    if handleData.requestState.contentLength > server.maxBodyLen:
      return true # Body is too large, close the connection

    if handleData.bytesReceived < handleData.requestState.contentLength:
      return false # Need to receive more bytes

    # We have the entire request body

    # If this request has a body, fill it
    if handleData.requestState.contentLength > 0:
      handleData.requestState.body.setLen(handleData.requestState.contentLength)
      copyMem(
        handleData.requestState.body[0].addr,
        handleData.recvBuffer[0].addr,
        handleData.requestState.contentLength
      )

    # Remove this request from the receive buffer
    let bytesRemaining =
      handleData.bytesReceived - handleData.requestState.contentLength
    copyMem(
      handleData.recvBuffer[0].addr,
      handleData.recvBuffer[handleData.requestState.contentLength].addr,
      bytesRemaining
    )
    handleData.bytesReceived = bytesRemaining

    var request = server.popRequest(clientSocket, handleData)
    acquire(server.requestQueueLock)
    server.requestQueue.addLast(move request)
    release(server.requestQueueLock)
    signal(server.requestQueueCond)

proc afterRecv(
  server: HttpServer,
  clientSocket: SocketHandle,
  handleData: HandleData
): bool {.raises: [IOSelectorsException].} =
  # Have we upgraded this connection to a websocket?
  # If not, treat incoming bytes as part of HTTP requests.
  if handleData.upgradedToWebSocket:
    server.afterRecvWebSocket(clientSocket, handleData)
  else:
    server.afterRecvHttp(clientSocket, handleData)

proc afterSend(
  server: HttpServer,
  clientSocket: SocketHandle,
  handleData: HandleData
): bool {.raises: [IOSelectorsException].} =
  let
    outgoingBuffer = handleData.outgoingBuffers.peekFirst()
    totalBytes = outgoingBuffer.buffer1.len + outgoingBuffer.buffer2.len
  if outgoingBuffer.bytesSent == totalBytes:
    handleData.outgoingBuffers.shrink(1)
    if outgoingBuffer.isCloseFrame:
      handleData.closeFrameSent = true
    if outgoingBuffer.closeConnection:
      return true
  if handleData.outgoingBuffers.len == 0:
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
        let eventHandleData = server.selector.getData(readyKey.fd)
        if eventHandleData.handleKind == ResponseQueuedEvent:
          acquire(server.responseQueueLock)
          let encodedResponse = server.responseQueue.popFirst()
          release(server.responseQueueLock)

          if encodedResponse.clientSocket in server.selector:
            let clientHandleData =
              server.selector.getData(encodedResponse.clientSocket)

            let outgoingBuffer = OutgoingBuffer()
            outgoingBuffer.closeConnection = encodedResponse.closeConnection
            outgoingBuffer.buffer1 = move encodedResponse.buffer1
            outgoingBuffer.buffer2 = move encodedResponse.buffer2
            clientHandleData.outgoingBuffers.addLast(outgoingBuffer)
            server.selector.updateHandle2(
              encodedResponse.clientSocket,
              {Read, Write}
            )

            if encodedResponse.isWebSocketUpgrade:
              clientHandleData.upgradedToWebSocket = true
              if clientHandleData.bytesReceived > 0:
                # Why have we received bytes when we are upgrading the connection?
                needClosing.add(readyKey.fd.SocketHandle)
                clientHandleData.sendsWaitingForUpgrade.setLen(0)
                continue
              # Are there any sends that were waiting for this response?
              if clientHandleData.sendsWaitingForUpgrade.len > 0:
                for encodedFrame in clientHandleData.sendsWaitingForUpgrade:
                  if clientHandleData.closeFrameQueued:
                    discard # Drop this message
                    # TODO: log?
                  else:
                    let outgoingBuffer = OutgoingBuffer()
                    outgoingBuffer.buffer1 = move encodedFrame.buffer1
                    outgoingBuffer.buffer2 = move encodedFrame.buffer2
                    outgoingBuffer.isCloseFrame = encodedFrame.isCloseFrame
                    clientHandleData.outgoingBuffers.addLast(outgoingBuffer)
                    if encodedFrame.isCloseFrame:
                      clientHandleData.closeFrameQueued = true
                clientHandleData.sendsWaitingForUpgrade.setLen(0)

        elif eventHandleData.handleKind == SendQueuedEvent:
          acquire(server.responseQueueLock)
          let encodedFrame = server.sendQueue.popFirst()
          release(server.responseQueueLock)

          if encodedFrame.clientSocket in server.selector:
            let clientHandleData =
              server.selector.getData(encodedFrame.clientSocket)

            # Have we sent the upgrade response yet?
            if clientHandleData.upgradedToWebSocket:
              if clientHandleData.closeFrameQueued:
                discard # Drop this message
                # TODO: log?
              else:
                let outgoingBuffer = OutgoingBuffer()
                outgoingBuffer.buffer1 = move encodedFrame.buffer1
                outgoingBuffer.buffer2 = move encodedFrame.buffer2
                outgoingBuffer.isCloseFrame = encodedFrame.isCloseFrame
                clientHandleData.outgoingBuffers.addLast(outgoingBuffer)
                if encodedFrame.isCloseFrame:
                  clientHandleData.closeFrameQueued = true
                server.selector.updateHandle2(
                  encodedFrame.clientSocket,
                  {Read, Write}
                )
            else:
              # If we haven't, queue this to wait for the upgrade response
              clientHandleData.sendsWaitingForUpgrade.add(encodedFrame)

        continue

      if readyKey.fd == server.socket.int:
        if Read in readyKey.events:
          let (clientSocket, _) = server.socket.accept()
          if clientSocket == osInvalidSocket:
            continue

          clientSocket.setBlocking(false)
          server.clientSockets.incl(clientSocket)

          let handleData = HandleData()
          handleData.handleKind = ClientSocket
          handleData.recvBuffer.setLen(initialRecvBufferLen)
          server.selector.registerHandle(clientSocket, {Read}, handleData)
      else:
        if Error in readyKey.events:
          needClosing.add(readyKey.fd.SocketHandle)
          continue

        let handleData = server.selector.getData(readyKey.fd)

        if Read in readyKey.events:
          # Expand the buffer if it is full
          if handleData.bytesReceived == handleData.recvBuffer.len:
            handleData.recvBuffer.setLen(handleData.recvBuffer.len * 2)

          let bytesReceived = readyKey.fd.SocketHandle.recv(
            handleData.recvBuffer[handleData.bytesReceived].addr,
            handleData.recvBuffer.len - handleData.bytesReceived,
            0
          )
          if bytesReceived > 0:
            handleData.bytesReceived += bytesReceived
            receivedFrom.add(readyKey.fd.SocketHandle)
          else:
            needClosing.add(readyKey.fd.SocketHandle)
            continue

        if Write in readyKey.events:
          let
            outgoingBuffer = handleData.outgoingBuffers.peekFirst()
            bytesSent =
              if outgoingBuffer.bytesSent < outgoingBuffer.buffer1.len:
                readyKey.fd.SocketHandle.send(
                  outgoingBuffer.buffer1[outgoingBuffer.bytesSent].addr,
                  outgoingBuffer.buffer1.len - outgoingBuffer.bytesSent,
                  0
                )
              else:
                let buffer2Pos =
                  outgoingBuffer.bytesSent - outgoingBuffer.buffer1.len
                readyKey.fd.SocketHandle.send(
                  outgoingBuffer.buffer2[buffer2Pos].addr,
                  outgoingBuffer.buffer2.len - buffer2Pos,
                  0
                )
          if bytesSent > 0:
            outgoingBuffer.bytesSent += bytesSent
            sentTo.add(readyKey.fd.SocketHandle)
          else:
            needClosing.add(readyKey.fd.SocketHandle)
            continue

    for clientSocket in receivedFrom:
      if clientSocket in needClosing:
        continue
      let
        handleData = server.selector.getData(clientSocket)
        needsClosing = server.afterRecv(clientSocket, handleData)
      if needsClosing:
        needClosing.add(clientSocket)

    for clientSocket in sentTo:
      if clientSocket in needClosing:
        continue
      let
        handleData = server.selector.getData(clientSocket)
        needsClosing = server.afterSend(clientSocket, handleData)
      if needsClosing:
        needClosing.add(clientSocket)

    for clientSocket in needClosing:
      try:
        server.selector.unregister(clientSocket)
      except:
        # Leaks HandleData for this socket
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

    server.selector = newSelector[HandleData]()

    let serverData = HandleData()
    serverData.handleKind = ServerSocket
    server.selector.registerHandle(server.socket, {Read}, serverData)

    let responseQueuedData = HandleData()
    responseQueuedData.handleKind = ResponseQueuedEvent
    server.selector.registerEvent(server.responseQueued, responseQueuedData)

    let sendQueuedData = HandleData()
    sendQueuedData.handleKind = SendQueuedEvent
    server.selector.registerEvent(server.sendQueued, sendQueuedData)
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

proc workerProc(server: ptr HttpServerObj) {.raises: [], gcsafe.} =
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
      server.handler(request, response)
    except:
      # TODO: log?
      response = HttpResponse()
      response.statusCode = 500

    # Be careful about looking at request, it may have been modified by handler

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

    encodedResponse.buffer1 = response.encodeHeaders()
    encodedResponse.buffer2 = move response.body

    encodedResponse.isWebSocketUpgrade = request.websocketUpgradeCalled

    acquire(server.responseQueueLock)
    server.responseQueue.addLast(move encodedResponse)
    release(server.responseQueueLock)

    server.responseQueued.trigger2()

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
  initLock(result.sendQueueLock)
  result.workerThreads.setLen(workerThreads)

  try:
    result.responseQueued = newSelectEvent()
    result.sendQueued = newSelectEvent()

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
    deinitLock(result.sendQueueLock)
    try:
      result.responseQueued.close()
    except:
      discard # Ignore
    try:
      result.sendQueued.close()
    except:
      discard # Ignore
    raise currentExceptionAsHttpServerError()
