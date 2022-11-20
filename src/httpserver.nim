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
    selector: Selector[SocketData]
    responseReady: SelectEvent
    clientSockets: HashSet[SocketHandle]
    requestQueue: Deque[HttpRequest]
    requestQueueLock: Lock
    requestQueueCond: Cond
    responseQueue: Deque[EncodedHttpResponse]
    responseQueueLock: Lock
    nextWebSocketId: uint64

  SocketData = ref object
    recvBuffer: string
    bytesReceived: int
    requestState: IncomingRequestState
    outgoingPayloads: Deque[OutgoingPayloadState]
    upgradedToWebSocket: bool

  IncomingRequestState = object
    headersParsed, chunked: bool
    contentLength: int
    httpVersion: HttpVersion
    httpMethod, uri: string
    headers: HttpHeaders
    body: string

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

# proc send*(websocket: WebSocket, data = "") =
#   discard

proc websocketUpgrade*(
  request: HttpRequest,
  response: var HttpResponse
): WebSocket {.raises: [HttpServerError].} =
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

proc encode(response: var HttpResponse): string =
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
  result.add response.body

  assert result.len == totalLen

proc updateHandle2(
  selector: Selector[SocketData],
  socket: SocketHandle,
  events: set[Event]
) {.raises: [IOSelectorsException].} =
  try:
    selector.updateHandle(socket, events)
  except ValueError: # Why ValueError?
    raise newException(IOSelectorsException, getCurrentExceptionMsg())

proc popRequest(
  server: HttpServer,
  clientSocket: SocketHandle,
  socketData: SocketData
): HttpRequest {.raises: [].} =
  ## Pops the completed HttpRequest from the socket and resets the parse state.
  result = HttpRequest()
  result.server = cast[ptr HttpServerObj](server)
  result.clientSocket = clientSocket
  result.httpVersion = socketData.requestState.httpVersion
  result.httpMethod = move socketData.requestState.httpMethod
  result.uri = move socketData.requestState.uri
  result.headers = move socketData.requestState.headers
  result.body = move socketData.requestState.body
  socketData.requestState = IncomingRequestState()

proc afterRecv(
  server: HttpServer,
  clientSocket: SocketHandle,
  socketData: SocketData
): bool {.raises: [].} =
  # Have we completed parsing the headers?
  if not socketData.requestState.headersParsed:
    # Not done with headers yet, look for the end of the headers
    let headersEnd = socketData.recvBuffer.find(
      "\r\n\r\n",
      0,
      min(socketData.bytesReceived, server.maxHeadersLen) - 1 # Inclusive
    )
    if headersEnd < 0: # Headers end not found
      if socketData.bytesReceived > server.maxHeadersLen:
        return true # Headers too long or malformed, close the connection
      return false # Try again after receiving more bytes

    # We have the headers, now to parse them
    var
      headerLines: seq[string]
      nextLineStart: int
    while true:
      let lineEnd = socketData.recvBuffer.find(
        "\r\n",
        nextLineStart,
        headersEnd
      )
      if lineEnd == -1:
        var line = socketData.recvBuffer[nextLineStart ..< headersEnd].strip()
        headerLines.add(move line)
        break
      else:
        headerLines.add(socketData.recvBuffer[nextLineStart ..< lineEnd].strip())
        nextLineStart = lineEnd + 2

    let
      requestLine = headerLines[0]
      requestLineParts = requestLine.split(" ")
    if requestLineParts.len != 3:
      return true # Malformed request line, close the connection

    socketData.requestState.httpMethod = requestLineParts[0]
    socketData.requestState.uri = requestLineParts[1]

    if requestLineParts[2] == "HTTP/1.0":
      socketData.requestState.httpVersion = Http10
    elif requestLineParts[2] == "HTTP/1.1":
      socketData.requestState.httpVersion = Http11
    else:
      return true # Unsupported HTTP version, close the connection

    for i in 1 ..< headerLines.len:
      let parts = headerLines[i].split(": ")
      if parts.len == 2:
        socketData.requestState.headers.add((parts[0], parts[1]))
      else:
        socketData.requestState.headers.add((headerLines[i], ""))

    socketData.requestState.chunked =
      socketData.requestState.headers.headerContainsToken(
        "Transfer-Encoding", "chunked"
      )

    # If this is a chunked request ignore any Content-Length headers
    if not socketData.requestState.chunked:
      var foundContentLength: bool
      for (k, v) in socketData.requestState.headers:
        if cmpIgnoreCase(k, "Content-Length") == 0:
          if foundContentLength:
            # This is a second Content-Length header, not valid
            return true # Close the connection
          foundContentLength = true
          try:
            socketData.requestState.contentLength = parseInt(v)
          except:
            return true # Parsing Content-Length failed, close the connection

      if socketData.requestState.contentLength < 0:
        return true # Invalid Content-Length, close the connection

    # Remove the headers from the receive buffer
    let bodyStart = headersEnd + 4
    if socketData.bytesReceived == bodyStart:
      socketData.bytesReceived = 0
    else:
      copyMem(
        socketData.recvBuffer[0].addr,
        socketData.recvBuffer[bodyStart].addr,
        socketData.bytesReceived - bodyStart
      )
      socketData.bytesReceived -= bodyStart

    # One of three possible states for request body:
    # 1) We received a Content-Length header, so we know the content length
    # 2) We received a Transfer-Encoding: chunked header
    # 3) Neither, so we assume a content length of 0

    # Mark that headers have been parsed, must end this block
    socketData.requestState.headersParsed = true

  # Headers have been parsed, now for the body

  if socketData.requestState.chunked: # Chunked request
    # Process as many chunks as we have
    while true:
      if socketData.bytesReceived < 3:
        return false # Need to receive more bytes

      # Look for the end of the chunk length
      let chunkLenEnd = socketData.recvBuffer.find(
        "\r\n",
        0,
        min(socketData.bytesReceived - 1, 19) # Inclusive with a reasonable max
      )
      if chunkLenEnd < 0: # Chunk length end not found
        if socketData.bytesReceived > 19:
          return true # We should have found it, close the connection
        return false # Try again after receiving more bytes

      var chunkLen: int
      try:
        discard parseHex(
          socketData.recvBuffer,
          chunkLen,
          0,
          chunkLenEnd
        )
      except:
        return true # Parsing chunk length failed, close the connection

      if socketData.requestState.contentLength + chunkLen > server.maxBodyLen:
        return true # Body is too large, close the connection

      let chunkStart = chunkLenEnd + 2
      if socketData.bytesReceived < chunkStart + chunkLen + 2:
        return false # Need to receive more bytes

      # Make room in the body buffer for this chunk
      let newContentLength = socketData.requestState.contentLength + chunkLen
      if socketData.requestState.body.len < newContentLength:
        let newLen = max(socketData.requestState.body.len * 2, newContentLength)
        socketData.requestState.body.setLen(newLen)

      copyMem(
        socketData.requestState.body[socketData.requestState.contentLength].addr,
        socketData.recvBuffer[chunkStart].addr,
        chunkLen
      )

      socketData.requestState.contentLength += chunkLen

      # Remove this chunk from the receive buffer
      let
        nextChunkStart = chunkLenEnd + 2 + chunkLen + 2
        bytesRemaining = socketData.bytesReceived - nextChunkStart
      copyMem(
        socketData.recvBuffer[0].addr,
        socketData.recvBuffer[nextChunkStart].addr,
        bytesRemaining
      )
      socketData.bytesReceived = bytesRemaining

      if chunkLen == 0:
        var request = server.popRequest(clientSocket, socketData)
        acquire(server.requestQueueLock)
        server.requestQueue.addLast(move request)
        release(server.requestQueueLock)
        signal(server.requestQueueCond)
        return false
  else:
    if socketData.requestState.contentLength > server.maxBodyLen:
      return true # Body is too large, close the connection

    if socketData.bytesReceived < socketData.requestState.contentLength:
      return false # Need to receive more bytes

    # We have the entire request body

    # If this request has a body, fill it
    if socketData.requestState.contentLength > 0:
      socketData.requestState.body.setLen(socketData.requestState.contentLength)
      copyMem(
        socketData.requestState.body[0].addr,
        socketData.recvBuffer[0].addr,
        socketData.requestState.contentLength
      )

    # Remove this request from the receive buffer
    let bytesRemaining =
      socketData.bytesReceived - socketData.requestState.contentLength
    copyMem(
      socketData.recvBuffer[0].addr,
      socketData.recvBuffer[socketData.requestState.contentLength].addr,
      bytesRemaining
    )
    socketData.bytesReceived = bytesRemaining

    var request = server.popRequest(clientSocket, socketData)
    acquire(server.requestQueueLock)
    server.requestQueue.addLast(move request)
    release(server.requestQueueLock)
    signal(server.requestQueueCond)

proc afterSend(
  server: HttpServer,
  clientSocket: SocketHandle,
  socketData: SocketData
): bool {.raises: [IOSelectorsException].} =
  let outgoingPayload = socketData.outgoingPayloads.peekFirst()
  if outgoingPayload.bytesSent == outgoingPayload.buffer.len:
    socketData.outgoingPayloads.shrink(1)
    if outgoingPayload.closeConnection:
      return true
  if socketData.outgoingPayloads.len == 0:
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
          let socketData = server.selector.getData(encodedResponse.clientSocket)

          if encodedResponse.websocketUpgrade:
            socketData.upgradedToWebSocket = true
            if socketData.bytesReceived > 0:
              # Why have we received bytes when we are upgrading the connection?
              needClosing.add(readyKey.fd.SocketHandle)
              continue

          var outgoingPayload = OutgoingPayloadState()
          outgoingPayload.closeConnection = encodedResponse.closeConnection
          outgoingPayload.buffer = move encodedResponse.buffer

          socketData.outgoingPayloads.addLast(move outgoingPayload)

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

          let socketData = SocketData()
          socketData.recvBuffer.setLen(initialRecvBufferLen)
          server.selector.registerHandle(clientSocket, {Read}, socketData)
      else:
        if Error in readyKey.events:
          needClosing.add(readyKey.fd.SocketHandle)
          continue

        let socketData = server.selector.getData(readyKey.fd)

        if Read in readyKey.events:
          # Expand the buffer if it is full
          if socketData.bytesReceived == socketData.recvBuffer.len:
            socketData.recvBuffer.setLen(socketData.recvBuffer.len * 2)

          let bytesReceived = readyKey.fd.SocketHandle.recv(
            socketData.recvBuffer[socketData.bytesReceived].addr,
            socketData.recvBuffer.len - socketData.bytesReceived,
            0
          )
          if bytesReceived > 0:
            socketData.bytesReceived += bytesReceived
            receivedFrom.add(readyKey.fd.SocketHandle)
          else:
            needClosing.add(readyKey.fd.SocketHandle)
            continue

        if Write in readyKey.events:
          let
            outgoingPayload = socketData.outgoingPayloads.peekFirst()
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
        socketData = server.selector.getData(clientSocket)
        needsClosing = server.afterRecv(clientSocket, socketData)
      if needsClosing:
        needClosing.add(clientSocket)

    for clientSocket in sentTo:
      if clientSocket in needClosing:
        continue
      let
        socketData = server.selector.getData(clientSocket)
        needsClosing = server.afterSend(clientSocket, socketData)
      if needsClosing:
        needClosing.add(clientSocket)

    for clientSocket in needClosing:
      try:
        server.selector.unregister(clientSocket)
      except:
        # Leaks SocketData for this socket
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

    server.selector = newSelector[SocketData]()
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
      # TODO log?
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
