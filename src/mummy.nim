when not defined(gcArc) and not defined(gcOrc):
  {.error: "Using --mm:arc or --mm:orc is required by Mummy.".}

when not compileOption("threads"):
  {.error: "Using --threads:on is required by Mummy.".}

import mummy/common, mummy/filelogger, mummy/internal, std/atomics, std/base64,
    std/cpuinfo, std/deques, std/hashes, std/nativesockets, std/os,
    std/parseutils, std/selectors, std/sets, std/sha1, std/strutils, std/tables,
    std/times, zippy

when defined(linux):
  when defined(nimdoc):
    # Why am I doing this?
    from posix import write, TPollfd, POLLIN, poll, close, EAGAIN, O_CLOEXEC, O_NONBLOCK
  else:
    import posix

  let SOCK_NONBLOCK
    {.importc: "SOCK_NONBLOCK", header: "<sys/socket.h>".}: cint

const useLockAndCond = (not defined(linux)) or defined(mummyUseLockAndCond)

when useLockAndCond:
  import std/locks
else:
  proc eventfd(count: cuint, flags: cint): cint
     {.cdecl, importc: "eventfd", header: "<sys/eventfd.h>".}

export Port, common, filelogger

const
  listenBacklogLen = 128
  maxEventsPerSelectLoop = 64
  initialRecvBufLen = (32 * 1024) - 9 # 8 byte cap field + null terminator

let
  http10 = "HTTP/1.0"
  http11 = "HTTP/1.1"

type
  ServeConfig* = object
    port*: Port
    address*: string
    certFile*, keyFile*: string

  RequestObj = object
    httpVersion*: HttpVersion
    httpMethod*: string
    uri*: string
    headers*: HttpHeaders
    body*: string
    server: Server
    clientSocket: SocketHandle
    responded: bool

  Request* = ptr RequestObj

  WebSocket* = object
    server: Server
    clientSocket: SocketHandle

  Message* = object
    kind*: MessageKind
    data*: string

  WebSocketEvent* = enum
    OpenEvent, MessageEvent, ErrorEvent, CloseEvent

  MessageKind* = enum
    TextMessage, BinaryMessage, Ping, Pong

  RequestHandler* = proc(request: Request) {.gcsafe.}

  WebSocketHandler* = proc(
    websocket: WebSocket,
    event: WebSocketEvent,
    message: Message
  ) {.gcsafe.}

  ServerObj = object
    handler: RequestHandler
    websocketHandler: WebSocketHandler
    logHandler: LogHandler
    maxHeadersLen, maxBodyLen, maxMessageLen: int
    workerThreads: seq[Thread[(Server, int)]]
    serveCalled, destroyCalled: Atomic[bool]
    serverSockets: seq[SocketHandle]
    selector: Selector[DataEntry]
    responseQueued, sendQueued, shutdown: SelectEvent
    clientSockets: HashSet[SocketHandle]
    when useLockAndCond:
      taskQueueLock: Lock
      taskQueueCond: Cond
    else:
      taskQueueLock: Atomic[bool]
      workerEventFds: seq[cint]
      destroyCalledFd: cint
      workersAwake: int
    taskQueue: Deque[WorkerTask]
    responseQueue: Deque[OutgoingBuffer]
    responseQueueLock: Atomic[bool]
    sendQueue: Deque[OutgoingBuffer]
    sendQueueLock: Atomic[bool]
    websocketClaimed: Table[WebSocket, bool]
    websocketQueues: Table[WebSocket, Deque[WebSocketUpdate]]
    websocketQueuesLock: Atomic[bool]

  Server* = ptr ServerObj

  WorkerTask = object
    request: Request
    websocket: WebSocket

  DataEntryKind = enum
    ServerSocketEntry, ClientSocketEntry, EventEntry

  DataEntry = ref object
    case kind: DataEntryKind:
    of ServerSocketEntry:
      discard
    of EventEntry:
      forEvent: SelectEvent
    of ClientSocketEntry:
      tlsStage: TlsStage
      recvBuf, tlsRecvBuf: string
      bytesReceived, tlsBytesReceived: int
      requestState: IncomingRequestState
      frameState: IncomingFrameState
      outgoingBuffers: Deque[OutgoingBuffer]
      closeFrameQueuedAt: float64
      upgradedToWebSocket, closeFrameSent: bool
      sendsWaitingForUpgrade: seq[OutgoingBuffer]
    # of ServerSocketEntry, ClientSocketEntry:
    port: Port
    address: string
    tls: bool

  TlsStage = enum
    NeedClientHello, NeedClientKey

  IncomingRequestState = object
    headersParsed, chunked: bool
    contentLength: int
    httpVersion: HttpVersion
    httpMethod, uri: string
    headers: HttpHeaders
    body: string

  IncomingFrameState = object
    opcode: uint8
    buffer: string
    frameLen: int

  OutgoingBuffer {.acyclic.} = ref object
    clientSocket: SocketHandle
    closeConnection, isWebSocketUpgrade, isCloseFrame: bool
    buf1, buf2: string
    bytesSent: int

  WebSocketUpdate {.acyclic.} = ref object
    event: WebSocketEvent
    message: Message

proc `$`*(request: Request): string =
  result = request.httpMethod & " " & request.uri & " "
  case request.httpVersion:
  of Http10:
    result &= "HTTP/1.0"
  else:
    result &= "HTTP/1.0"
  result &= " (" & $cast[uint](request) & ")"

proc `$`*(websocket: WebSocket): string =
  "WebSocket " & $cast[uint](hash(websocket))

proc hash*(websocket: WebSocket): Hash =
  var h: Hash
  h = h !& hash(websocket.server)
  h = h !& hash(websocket.clientSocket)
  return !$h

template withLock(lock: var Atomic[bool], body: untyped): untyped =
  # TAS
  while lock.exchange(true, moAcquire): # Until we get the lock
    discard
  try:
    body
  finally:
    lock.store(false, moRelease)

proc log(server: Server, level: LogLevel, args: varargs[string]) =
  if server.logHandler == nil:
    return
  try:
    server.logHandler(level, args)
  except:
    discard # ???

proc headerContainsToken(headers: var HttpHeaders, key, token: string): bool =
  for (k, v) in headers:
    if cmpIgnoreCase(k, key) == 0:
      var first = 0
      while first < v.len:
        var comma = v.find(',', start = first)
        if comma == -1:
          comma = v.len
        var len = comma - first
        while len > 0 and v[first] in Whitespace:
          inc first
          dec len
        while len > 0 and v[first + len - 1] in Whitespace:
          dec len
        if len > 0 and len == token.len:
          var matches = true
          for i in 0 ..< len:
            if ord(toLowerAscii(v[first + i])) != ord(toLowerAscii(token[i])):
              matches = false
              break
          if matches:
            return true
        first = comma + 1

proc registerHandle2(
  selector: Selector[DataEntry],
  socket: SocketHandle,
  events: set[Event],
  data: DataEntry
) {.raises: [IOSelectorsException].} =
  try:
    selector.registerHandle(socket, events, data)
  except ValueError: # Why ValueError?
    raise newException(IOSelectorsException, getCurrentExceptionMsg())

proc updateHandle2(
  selector: Selector[DataEntry],
  socket: SocketHandle,
  events: set[Event]
) {.raises: [IOSelectorsException].} =
  try:
    selector.updateHandle(socket, events)
  except ValueError: # Why ValueError?
    raise newException(IOSelectorsException, getCurrentExceptionMsg())

proc trigger(
  server: Server,
  event: SelectEvent
) {.raises: [].} =
  while true:
    try:
      event.trigger()
    except:
      let err = osLastError()
      when defined(linux):
        if err == OSErrorCode(EAGAIN):
          continue
      server.log(
        ErrorLevel,
        "Error triggering event ", $err, " ", osErrorMsg(err)
      )
    break

when not useLockAndCond:
  proc trigger(server: Server, efd: cint) {.raises: [].} =
    var v: uint64 = 1
    while true:
      let ret = write(efd, v.addr, sizeof(uint64))
      if ret != sizeof(uint64):
        let err = osLastError()
        if err == OSErrorCode(EAGAIN):
          continue
        server.log(
          ErrorLevel,
          "Error writing to eventfd ", $err, " ", osErrorMsg(err)
        )
      break

proc send*(
  websocket: WebSocket,
  data: sink string,
  kind = TextMessage,
) {.raises: [], gcsafe.} =
  ## Enqueues the message to be sent over the WebSocket connection.

  var encodedFrame = OutgoingBuffer()
  encodedFrame.clientSocket = websocket.clientSocket

  case kind:
  of TextMessage:
    encodedFrame.buf1 = encodeFrameHeader(0x1, data.len)
  of BinaryMessage:
    encodedFrame.buf1 = encodeFrameHeader(0x2, data.len)
  of Ping:
    encodedFrame.buf1 = encodeFrameHeader(0x9, data.len)
  of Pong:
    encodedFrame.buf1 = encodeFrameHeader(0xA, data.len)

  encodedFrame.buf2 = move data

  var queueWasEmpty: bool
  withLock websocket.server.sendQueueLock:
    queueWasEmpty = websocket.server.sendQueue.len == 0
    websocket.server.sendQueue.addLast(move encodedFrame)

  if queueWasEmpty:
    websocket.server.trigger(websocket.server.sendQueued)

proc close*(websocket: WebSocket) {.raises: [], gcsafe.} =
  ## Begins the WebSocket closing handshake.
  ## This does not discard previously queued messages before starting the
  ## closing handshake.
  ## The handshake will only begin after the queued messages are sent.

  var encodedFrame = OutgoingBuffer()
  encodedFrame.clientSocket = websocket.clientSocket
  encodedFrame.buf1 = encodeFrameHeader(0x8, 0)
  encodedFrame.isCloseFrame = true

  var queueWasEmpty: bool
  withLock websocket.server.sendQueueLock:
    queueWasEmpty = websocket.server.sendQueue.len == 0
    websocket.server.sendQueue.addLast(move encodedFrame)

  if queueWasEmpty:
    websocket.server.trigger(websocket.server.sendQueued)

proc respond*(
  request: Request,
  statusCode: int,
  headers: sink HttpHeaders = newSeq[(string, string)](),
  body: sink string = ""
) {.raises: [], gcsafe.} =
  ## Sends the response for the request.
  ## This should usually only be called once per request.

  var encodedResponse = OutgoingBuffer()
  encodedResponse.clientSocket = request.clientSocket
  encodedResponse.closeConnection =
    request.httpVersion == Http10 # Default behavior

  # Override default behavior based on request Connection header
  if request.headers.headerContainsToken("Connection", "close"):
    encodedResponse.closeConnection = true
  elif request.headers.headerContainsToken("Connection", "keep-alive"):
    encodedResponse.closeConnection = false

  # If we are not already going to close the connection based on the request
  # headers, check if we should based on the response headers
  if not encodedResponse.closeConnection:
    encodedResponse.closeConnection = headers.headerContainsToken(
      "Connection", "close"
    )

  if encodedResponse.closeConnection:
    headers["Connection"] = "close"
  elif request.httpVersion == Http10:
    headers["Connection"] = "keep-alive"

  # If the body is big enough to justify compressing and not already compressed
  if body.len > 128 and "Content-Encoding" notin headers:
    if request.headers.headerContainsToken("Accept-Encoding", "gzip"):
      try:
        body = compress(body.cstring, body.len, BestSpeed, dfGzip)
        headers["Content-Encoding"] = "gzip"
      except:
        # This should never happen since exceptions are only thrown if
        # the data format is invalid or the level is invalid
        discard
    elif request.headers.headerContainsToken("Accept-Encoding", "deflate"):
      try:
        body = compress(body.cstring, body.len, BestSpeed, dfDeflate)
        headers["Content-Encoding"] = "deflate"
      except:
        # See gzip
        discard
    else:
      discard

  headers["Content-Length"] = $body.len

  encodedResponse.buf1 = encodeHeaders(statusCode, headers)
  if encodedResponse.buf1.len + body.len < 32 * 1024:
    # There seems to be a harsh penalty on multiple send() calls on Linux
    # so just use 1 buffer if the body is small enough
    encodedResponse.buf1 &= body
  else:
    encodedResponse.buf2 = move body
  encodedResponse.isWebSocketUpgrade = headers.headerContainsToken(
    "Upgrade",
    "websocket"
  )

  request.responded = true

  var queueWasEmpty: bool
  withLock request.server.responseQueueLock:
    queueWasEmpty = request.server.responseQueue.len == 0
    request.server.responseQueue.addLast(move encodedResponse)

  if queueWasEmpty:
    request.server.trigger(request.server.responseQueued)

proc upgradeToWebSocket*(
  request: Request
): WebSocket {.raises: [MummyError], gcsafe.} =
  ## Upgrades the request to a WebSocket connection. You can immediately start
  ## calling send().

  if not request.headers.headerContainsToken("Connection", "upgrade"):
    raise newException(
      MummyError,
      "Invalid request to upgade, missing 'Connection: upgrade' header"
    )

  if not request.headers.headerContainsToken("Upgrade", "websocket"):
    raise newException(
      MummyError,
      "Invalid request to upgade, missing 'Upgrade: websocket' header"
    )

  let websocketKey = request.headers["Sec-WebSocket-Key"]
  if websocketKey == "":
    raise newException(
      MummyError,
      "Invalid request to upgade, missing Sec-WebSocket-Key header"
    )

  let websocketVersion = request.headers["Sec-WebSocket-Version"]
  if websocketVersion != "13":
    raise newException(
      MummyError,
      "Invalid request to upgade, missing Sec-WebSocket-Version header"
    )

  # Looks good to upgrade

  result.server = request.server
  result.clientSocket = request.clientSocket

  let hash =
    secureHash(websocketKey & "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").Sha1Digest

  var headers: HttpHeaders
  headers["Connection"] = "upgrade"
  headers["Upgrade"] = "websocket"
  headers["Sec-WebSocket-Accept"] = base64.encode(hash)

  request.respond(101, headers, "")

proc workerProc(params: (Server, int)) {.raises: [].} =
  # The worker threads run the task queue here
  let
    server = params[0]
    threadIdx = params[1]

  proc runTask(task: WorkerTask) =
    if task.request != nil:
      try:
        server.handler(task.request)
      except:
        if not task.request.responded:
          task.request.respond(500)
        let e = getCurrentException()
        server.log(ErrorLevel, e.msg & "\n" & e.getStackTrace())
      `=destroy`(task.request[])
      deallocShared(task.request)
    else: # WebSocket
      withLock server.websocketQueuesLock:
        if server.websocketClaimed.getOrDefault(task.websocket, true):
          # If this websocket has been claimed or if it is not present in
          # the table (which indicates it has been closed), skip this task
          return
        # Claim this websocket
        server.websocketClaimed[task.websocket] = true

      while true: # Process the entire websocket queue
        var update: WebSocketUpdate
        withLock server.websocketQueuesLock:
          try:
            if server.websocketQueues[task.websocket].len > 0:
              update = server.websocketQueues[task.websocket].popFirst()
              if update.event == CloseEvent:
                server.websocketQueues.del(task.websocket)
                server.websocketClaimed.del(task.websocket)
            else:
              server.websocketClaimed[task.websocket] = false
          except KeyError:
            discard # Not possible

        if update == nil:
          break

        try:
          server.websocketHandler(
            task.websocket,
            update.event,
            move update.message
          )
        except:
          let e = getCurrentException()
          server.log(ErrorLevel, e.msg & "\n" & e.getStackTrace())

        if update.event == CloseEvent:
          break

  when useLockAndCond:
    while true:
      acquire(server.taskQueueLock)

      while server.taskQueue.len == 0 and
        not server.destroyCalled.load(moRelaxed):
        wait(server.taskQueueCond, server.taskQueueLock)

      if server.destroyCalled.load(moRelaxed):
        release(server.taskQueueLock)
        return

      let task = server.taskQueue.popFirst()
      release(server.taskQueueLock)

      runTask(task)
  else:
    var pollFds: array[2, TPollfd]
    pollFds[0].fd = server.workerEventFds[threadIdx]
    pollFds[0].events = POLLIN
    pollFds[1].fd = server.destroyCalledFd
    pollFds[1].events = POLLIN

    while true:
      if server.destroyCalled.load(moRelaxed):
        break
      var
        task: WorkerTask
        poppedTask: bool
      withLock server.taskQueueLock:
        if server.taskQueue.len > 0:
          task = server.taskQueue.popFirst()
          poppedTask = true
      if poppedTask:
        runTask(task)
      else:
        # Go to sleep if there are no tasks to run
        discard poll(pollFds[0].addr, 2, -1)
        if pollFds[0].revents != 0:
          var data: uint64 = 0
          while true:
            let ret = posix.read(pollFds[0].fd, data.addr, sizeof(uint64))
            if ret != sizeof(uint64):
              let err = osLastError()
              if err == OSErrorCode(EAGAIN):
                continue
              server.log(
                ErrorLevel,
                "Error reading eventfd ", $err, " ", osErrorMsg(err)
              )
            break

proc postTask(server: Server, task: WorkerTask) {.raises: [].} =
  when useLockAndCond:
    withLock server.taskQueueLock:
      server.taskQueue.addLast(task)
    signal(server.taskQueueCond)
  else:
    withLock server.taskQueueLock:
      # If the task queue is not empty, no threads could have fallen asleep
      # If the task queue is empty, any number could have fallen asleep
      if server.taskQueue.len == 0:
        server.workersAwake = 0
      server.taskQueue.addLast(task)

    if server.workersAwake < server.workerThreads.len:
      # Wake up a worker
      server.trigger(server.workerEventFds[server.workersAwake])
      inc server.workersAwake

proc postWebSocketUpdate(
  websocket: WebSocket,
  update: WebSocketUpdate
) {.raises: [].} =
  if websocket.server.websocketHandler == nil:
    websocket.server.log(DebugLevel, "WebSocket event but no WebSocket handler")
    return

  var needsTask: bool

  withLock websocket.server.websocketQueuesLock:
    if websocket notin websocket.server.websocketQueues:
      return

    try:
      websocket.server.websocketQueues[websocket].addLast(update)
      if not websocket.server.websocketClaimed[websocket]:
        needsTask = true
    except KeyError:
      discard # Not possible

  if needsTask:
    websocket.server.postTask(WorkerTask(websocket: websocket))

proc sendCloseFrame(
  server: Server,
  clientSocket: SocketHandle,
  dataEntry: DataEntry,
  closeConnection: bool
) {.raises: [IOSelectorsException].} =
  let outgoingBuffer = OutgoingBuffer()
  outgoingBuffer.buf1 = encodeFrameHeader(0x8, 0)
  outgoingBuffer.isCloseFrame = true
  outgoingBuffer.closeConnection = closeConnection
  dataEntry.outgoingBuffers.addLast(outgoingBuffer)
  dataEntry.closeFrameQueuedAt = epochTime()
  server.selector.updateHandle2(clientSocket, {Read, Write})

proc afterRecvWebSocket(
  server: Server,
  clientSocket: SocketHandle,
  dataEntry: DataEntry
): bool {.raises: [IOSelectorsException].} =
  if dataEntry.closeFrameQueuedAt > 0 and
    epochTime() - dataEntry.closeFrameQueuedAt > 10:
    # The Close frame dance didn't work out, just close the connection
    return true

  # Try to parse entire frames out of the receive buffer
  while true:
    if dataEntry.bytesReceived < 2:
      return false # Need to receive more bytes

    let
      b0 = dataEntry.recvBuf[0].uint8
      b1 = dataEntry.recvBuf[1].uint8
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

    if opcode == 0 and dataEntry.frameState.opcode == 0:
      # Per spec, the first frame must have an opcode > 0
      return true # Close the connection

    if dataEntry.frameState.opcode != 0 and opcode != 0:
      # Per spec, if we have buffered fragments the opcode must be 0
      return true # Close the connection

    var pos = 2

    var payloadLen = (b1 and 0b01111111).int
    if payloadLen <= 125:
      discard
    elif payloadLen == 126:
      if dataEntry.bytesReceived < 4:
        return false # Need to receive more bytes
      var l: uint16
      copyMem(l.addr, dataEntry.recvBuf[pos].addr, 2)
      payloadLen = nativesockets.htons(l).int
      pos += 2
    else:
      if dataEntry.bytesReceived < 10:
        return false # Need to receive more bytes
      var l: uint32
      copyMem(l.addr, dataEntry.recvBuf[pos + 4].addr, 4)
      payloadLen = nativesockets.htonl(l).int
      pos += 8

    if dataEntry.frameState.frameLen + payloadLen > server.maxMessageLen:
      server.log(DebugLevel, "Dropped WebSocket, message too long")
      return true # Message is too large, close the connection

    if dataEntry.bytesReceived < pos + 4:
      return false # Need to receive more bytes

    var mask: array[4, uint8]
    copyMem(mask.addr, dataEntry.recvBuf[pos].addr, 4)

    pos += 4

    if dataEntry.bytesReceived < pos + payloadLen:
      return false # Need to receive more bytes

    # Unmask the payload
    for i in 0 ..< payloadLen:
      let j = i mod 4
      dataEntry.recvBuf[pos + i] =
        (dataEntry.recvBuf[pos + i].uint8 xor mask[j]).char

    if dataEntry.frameState.opcode == 0:
      # This is the first fragment
      dataEntry.frameState.opcode = opcode

    # Make room in the message buffer for this fragment
    let newFrameLen = dataEntry.frameState.frameLen + payloadLen
    if dataEntry.frameState.buffer.len < newFrameLen:
      let newBufferLen = max(dataEntry.frameState.buffer.len * 2, newFrameLen)
      dataEntry.frameState.buffer.setLen(newBufferLen)

    if payloadLen > 0:
      # Copy the fragment into the message buffer
      copyMem(
        dataEntry.frameState.buffer[dataEntry.frameState.frameLen].addr,
        dataEntry.recvBuf[pos].addr,
        payloadLen
      )
      dataEntry.frameState.frameLen += payloadLen

    # Remove this frame from the receive buffer
    let frameLen = pos + payloadLen
    if dataEntry.bytesReceived == frameLen:
      dataEntry.bytesReceived = 0
    else:
      copyMem(
        dataEntry.recvBuf[0].addr,
        dataEntry.recvBuf[frameLen].addr,
        dataEntry.bytesReceived - frameLen
      )
      dataEntry.bytesReceived -= frameLen

    if fin:
      let frameOpcode = dataEntry.frameState.opcode

      # We have a full message

      var message: Message
      message.data = move dataEntry.frameState.buffer
      message.data.setLen(dataEntry.frameState.frameLen)

      dataEntry.frameState = IncomingFrameState()

      case frameOpcode:
      of 0x1: # Text
        message.kind = TextMessage
      of 0x2: # Binary
        message.kind = BinaryMessage
      of 0x8: # Close
        # If we already queued a close, just close the connection
        # This is not quite perfect
        if dataEntry.closeFrameQueuedAt > 0:
          return true # Close the connection
        # Otherwise send a Close in response then close the connection
        server.sendCloseFrame(clientSocket, dataEntry, true)
        continue
      of 0x9: # Ping
        message.kind = Ping
      of 0xA: # Pong
        message.kind = Pong
      else:
        server.log(DebugLevel, "Dropped WebSocket, received invalid opcode")
        return true # Invalid opcode, close the connection

      let
        websocket = WebSocket(
          server: server,
          clientSocket: clientSocket
        )
        update = WebSocketUpdate(
          event: MessageEvent,
          message: move message
        )
      websocket.postWebSocketUpdate(update)

proc popRequest(
  server: Server,
  clientSocket: SocketHandle,
  dataEntry: DataEntry
): Request {.raises: [].} =
  ## Pops the completed HttpRequest from the socket and resets the parse state.
  result = cast[Request](allocShared0(sizeof(RequestObj)))
  result.server = server
  result.clientSocket = clientSocket
  result.httpVersion = dataEntry.requestState.httpVersion
  result.httpMethod = move dataEntry.requestState.httpMethod
  result.uri = move dataEntry.requestState.uri
  result.headers = move dataEntry.requestState.headers
  result.body = move dataEntry.requestState.body
  result.body.setLen(dataEntry.requestState.contentLength)
  dataEntry.requestState = IncomingRequestState()

proc afterRecvHttp(
  server: Server,
  clientSocket: SocketHandle,
  dataEntry: DataEntry
): bool {.raises: [].} =
  # Have we completed parsing the headers?
  if not dataEntry.requestState.headersParsed:
    # Not done with headers yet, look for the end of the headers
    let headersEnd = dataEntry.recvBuf.find(
      "\r\n\r\n",
      0,
      min(dataEntry.bytesReceived, server.maxHeadersLen) - 1 # Inclusive
    )
    if headersEnd < 0: # Headers end not found
      if dataEntry.bytesReceived > server.maxHeadersLen:
        server.log(DebugLevel, "Dropped connection, headers too long")
        return true # Headers too long or malformed, close the connection
      return false # Try again after receiving more bytes

    # We have the headers, now to parse them

    var lineNum, lineStart: int
    while lineStart < headersEnd:
      var lineEnd = dataEntry.recvBuf.find(
        "\r\n",
        lineStart,
        headersEnd
      )
      if lineEnd == -1:
        lineEnd = headersEnd

      var lineLen = lineEnd - lineStart
      while lineLen > 0 and dataEntry.recvBuf[lineStart] in Whitespace:
        inc lineStart
        dec lineLen
      while lineLen > 0 and
        dataEntry.recvBuf[lineStart + lineLen - 1] in Whitespace:
        dec lineLen

      if lineNum == 0: # This is the request line
        let space1 = dataEntry.recvBuf.find(
          ' ',
          lineStart,
          lineStart + lineLen - 1
        )
        if space1 == -1:
          return true # Invalid request line, close the connection
        dataEntry.requestState.httpMethod = dataEntry.recvBuf[lineStart ..< space1]
        let
          remainingLen = lineLen - (space1 + 1 - lineStart)
          space2 = dataEntry.recvBuf.find(
            ' ',
            space1 + 1,
            space1 + 1 + remainingLen - 1
          )
        if space2 == -1:
          return true # Invalid request line, close the connection
        dataEntry.requestState.uri = dataEntry.recvBuf[space1 + 1 ..< space2]
        if dataEntry.recvBuf.find(
          ' ',
          space2 + 1,
          lineStart + lineLen - 1
        ) != -1:
          return true # Invalid request line, close the connection
        let httpVersionLen = lineLen - (space2 + 1 - lineStart)
        if httpVersionLen != 8:
          return true # Invalid request line, close the connection
        if equalMem(
          dataEntry.recvBuf[space2 + 1].addr,
          http11[0].unsafeAddr,
          8
        ):
          dataEntry.requestState.httpVersion = Http11
        elif equalMem(
          dataEntry.recvBuf[space2 + 1].addr,
          http10[0].unsafeAddr,
          8
        ):
          dataEntry.requestState.httpVersion = Http10
        else:
          return true # Unsupported HTTP version, close the connection
      else: # This is a header
        let splitAt = dataEntry.recvBuf.find(
          ':',
          lineStart,
          lineStart + lineLen - 1
        )
        if splitAt == -1:
          # Malformed header, include it for debugging purposes
          var line = dataEntry.recvBuf[lineStart ..< lineStart + lineLen]
          dataEntry.requestState.headers.add((move line, ""))
        else:
          var
            leftStart = lineStart
            leftLen = splitAt - leftStart
            rightStart = splitAt + 1
            rightLen = lineStart + lineLen - rightStart

          while leftLen > 0 and
            dataEntry.recvBuf[leftStart] in Whitespace:
            inc leftStart
            dec leftLen
          while leftLen > 0 and
            dataEntry.recvBuf[leftStart + leftLen - 1] in Whitespace:
            dec leftLen
          while rightLen > 0 and
            dataEntry.recvBuf[rightStart] in Whitespace:
            inc rightStart
            dec rightLen
          while leftLen > 0 and
            dataEntry.recvBuf[rightStart + rightLen - 1] in Whitespace:
            dec rightLen

          dataEntry.requestState.headers.add((
            dataEntry.recvBuf[leftStart ..< leftStart + leftLen],
            dataEntry.recvBuf[rightStart ..< rightStart + rightLen]
          ))

      lineStart = lineEnd + 2
      inc lineNum

    dataEntry.requestState.chunked =
      dataEntry.requestState.headers.headerContainsToken(
        "Transfer-Encoding", "chunked"
      )

    # If this is a chunked request ignore any Content-Length headers
    if not dataEntry.requestState.chunked:
      var foundContentLength: bool
      for (k, v) in dataEntry.requestState.headers:
        if cmpIgnoreCase(k, "Content-Length") == 0:
          if foundContentLength:
            # This is a second Content-Length header, not valid
            return true # Close the connection
          foundContentLength = true
          try:
            dataEntry.requestState.contentLength = parseInt(v)
          except:
            return true # Parsing Content-Length failed, close the connection

      if dataEntry.requestState.contentLength < 0:
        return true # Invalid Content-Length, close the connection

    # Remove the headers from the receive buffer
    # We do this so we can hopefully just move the receive buffer at the end
    # instead of always copying a potentially huge body
    let bodyStart = headersEnd + 4
    if dataEntry.bytesReceived == bodyStart:
      dataEntry.bytesReceived = 0
    else:
      # This could be optimized away by having [0] be [head] where head can move
      # without having to copy the headers out
      copyMem(
        dataEntry.recvBuf[0].addr,
        dataEntry.recvBuf[bodyStart].addr,
        dataEntry.bytesReceived - bodyStart
      )
      dataEntry.bytesReceived -= bodyStart

    # One of three possible states for request body:
    # 1) We received a Content-Length header, so we know the content length
    # 2) We received a Transfer-Encoding: chunked header
    # 3) Neither, so we assume a content length of 0

    # Mark that headers have been parsed, must end this block
    dataEntry.requestState.headersParsed = true

  # Headers have been parsed, now for the body

  if dataEntry.requestState.chunked: # Chunked request
    # Process as many chunks as we have
    while true:
      if dataEntry.bytesReceived < 3:
        return false # Need to receive more bytes

      # Look for the end of the chunk length
      let chunkLenEnd = dataEntry.recvBuf.find(
        "\r\n",
        0,
        min(dataEntry.bytesReceived - 1, 19) # Inclusive with a reasonable max
      )
      if chunkLenEnd < 0: # Chunk length end not found
        if dataEntry.bytesReceived > 19:
          return true # We should have found it, close the connection
        return false # Try again after receiving more bytes

      # After we know we've seen the end of the chunk length, parse it
      var chunkLen: int
      try:
        discard parseHex(
          dataEntry.recvBuf,
          chunkLen,
          0,
          chunkLenEnd
        )
      except:
        return true # Parsing chunk length failed, close the connection

      if dataEntry.requestState.contentLength + chunkLen > server.maxBodyLen:
        server.log(DebugLevel, "Dropped connection, body too long")
        return true # Body is too large, close the connection

      let chunkStart = chunkLenEnd + 2
      if dataEntry.bytesReceived < chunkStart + chunkLen + 2:
        return false # Need to receive more bytes

      # Make room in the body buffer for this chunk
      let newContentLength = dataEntry.requestState.contentLength + chunkLen
      if dataEntry.requestState.body.len < newContentLength:
        let newLen = max(dataEntry.requestState.body.len * 2, newContentLength)
        dataEntry.requestState.body.setLen(newLen)

      if chunkLen > 0:
        copyMem(
          dataEntry.requestState.body[dataEntry.requestState.contentLength].addr,
          dataEntry.recvBuf[chunkStart].addr,
          chunkLen
        )
        dataEntry.requestState.contentLength += chunkLen

      # Remove this chunk from the receive buffer
      let
        nextChunkStart = chunkLenEnd + 2 + chunkLen + 2
        bytesRemaining = dataEntry.bytesReceived - nextChunkStart
      copyMem(
        dataEntry.recvBuf[0].addr,
        dataEntry.recvBuf[nextChunkStart].addr,
        bytesRemaining
      )
      dataEntry.bytesReceived = bytesRemaining

      if chunkLen == 0: # A chunk of len 0 marks the end of the request body
        let request = server.popRequest(clientSocket, dataEntry)
        server.postTask(WorkerTask(request: request))
  else:
    if dataEntry.requestState.contentLength > server.maxBodyLen:
      server.log(DebugLevel, "Dropped connection, body too long")
      return true # Body is too large, close the connection

    if dataEntry.bytesReceived < dataEntry.requestState.contentLength:
      return false # Need to receive more bytes

    # We have the entire request body

    # If this request has a body
    if dataEntry.requestState.contentLength > 0:
      # If the receive buffer only has the body in it, just move it and reset
      # the receive buffer
      if dataEntry.requestState.contentLength == dataEntry.bytesReceived:
        dataEntry.requestState.body = move dataEntry.recvBuf
        dataEntry.recvBuf.setLen(initialRecvBufLen)
      else:
        # Copy the body out of the buffer
        dataEntry.requestState.body.setLen(
            dataEntry.requestState.contentLength)
        copyMem(
          dataEntry.requestState.body[0].addr,
          dataEntry.recvBuf[0].addr,
          dataEntry.requestState.contentLength
        )
        # Remove this request from the receive buffer
        let bytesRemaining =
          dataEntry.bytesReceived - dataEntry.requestState.contentLength
        copyMem(
          dataEntry.recvBuf[0].addr,
          dataEntry.recvBuf[dataEntry.requestState.contentLength].addr,
          bytesRemaining
        )
        dataEntry.bytesReceived = bytesRemaining

    let request = server.popRequest(clientSocket, dataEntry)
    server.postTask(WorkerTask(request: request))

proc afterRecvTls(
  server: Server,
  clientSocket: SocketHandle,
  dataEntry: DataEntry
): bool {.raises: [].} =
  # Each TLS record starts with 5 header bytes
  if dataEntry.tlsBytesReceived < 5:
    return false # Need to receive more bytes

  case dataEntry.tlsStage:
  of NeedClientHello:
    if dataEntry.tlsRecvBuf[0].uint8 != 22:
      return true # Invalid TLS record type, close the connection

    if dataEntry.tlsRecvBuf[1].uint8 != 3 or
      dataEntry.tlsRecvBuf[2].uint8 != 1:
      return true # Invalid protocol version, close the connection

    let fragmentLen = block:
      var l: uint16
      copyMem(l.addr, dataEntry.tlsRecvBuf[3].addr, 2)
      nativesockets.htons(l).int

    if fragmentLen > server.maxBodyLen:
      server.log(DebugLevel, "Dropped connection, body too long")
      return true # Body is too large, close the connection

    if dataEntry.tlsBytesReceived < fragmentLen:
      return false # Need to receive more bytes

    if dataEntry.tlsBytesReceived > fragmentLen + 5:
      return true # Why do we have unexpected bytes?

    # We have the fragment

    var pos = 5 # Relative to tlsRecvBuf[0] and tlsBytesReceived, not fragmentLen

    if fragmentLen < 4 + 2 + 32 + 1:
      return true # Invalid fragment, close the connection

    if dataEntry.tlsRecvBuf[pos].uint8 != 1:
      return true # Not ClientHello, close the connection

    inc pos

    let clientHelloLen = block:
      var l: uint32
      copyMem(l.addr, dataEntry.tlsRecvBuf[pos].addr, 3)
      l = (l shl 8) # Only read 3 big-endian bytes, shift into place
      nativesockets.htonl(l).int

    pos += 3

    if clientHelloLen + 4 != fragmentLen:
      return true # Invalid fragment, close the connection

    if dataEntry.tlsRecvBuf[pos].uint8 != 3 or
      dataEntry.tlsRecvBuf[pos + 1].uint8 != 3:
      return true # Invalid protocol version, close the connection

    pos += 2

    var clientRandom: array[32, uint8]
    copyMem(clientRandom[0].addr, dataEntry.tlsRecvBuf[pos].addr, 3)

    pos += 32

    let sessionIdLen = dataEntry.tlsRecvBuf[pos].int

    inc pos

    if pos + sessionIdLen > dataEntry.tlsBytesReceived:
      return true # Invalid fragment, close the connection

    # if sessionIdLen > 0:
    #   var sessionId = newString(sessionIdLen)
    #   copyMem(sessionId[0].addr, dataEntry.tlsRecvBuf[pos].addr, sessionIdLen)

    pos += sessionIdLen

    if pos + 2 > dataEntry.tlsBytesReceived:
      return true # Invalid fragment, close the connection

    let cypherSuiteDataLen = block:
      var l: uint16
      copyMem(l.addr, dataEntry.tlsRecvBuf[pos].addr, 2)
      nativesockets.htons(l).int

    pos += 2

    if cypherSuiteDataLen mod 2 != 0:
      return true # Invalid fragment, close the connection

    if pos + cypherSuiteDataLen > dataEntry.tlsBytesReceived:
      return true # Invalid fragment, close the connection

    var TLS_CHACHA20_POLY1305_SHA256: bool
    for i in 0 ..< cypherSuiteDataLen div 2:
      if dataEntry.tlsRecvBuf[pos + i * 2].uint8 == 0x13 and
        dataEntry.tlsRecvBuf[pos + i * 2 + 1].uint8 == 0x03:
        TLS_CHACHA20_POLY1305_SHA256 = true
        break

    pos += cypherSuiteDataLen

    if TLS_CHACHA20_POLY1305_SHA256:
      echo "GOTCHA"

    if pos + 1 > dataEntry.tlsBytesReceived:
      return true # Invalid fragment, close the connection

    let compressionMethodsLen = dataEntry.tlsRecvBuf[pos].int

    inc pos

    if pos + compressionMethodsLen > dataEntry.tlsBytesReceived:
      return true # Invalid fragment, close the connection

    pos += compressionMethodsLen

    let extensionsLen = block:
      var l: uint16
      copyMem(l.addr, dataEntry.tlsRecvBuf[pos].addr, 2)
      nativesockets.htons(l).int

    pos += 2

    if pos + extensionsLen > dataEntry.tlsBytesReceived:
      return true # Invalid fragment, close the connection

    while true:
      if pos + 4 > dataEntry.tlsBytesReceived:
        return true # Invalid fragment, close the connection

      var extensionType: array[2, uint8]
      copyMem(extensionType[0].addr, dataEntry.tlsRecvBuf[pos].addr, 2)

      pos += 2

      let extensionLen = block:
        var l: uint16
        copyMem(l.addr, dataEntry.tlsRecvBuf[pos].addr, 2)
        nativesockets.htons(l).int

      pos += 2

      if extensionType == [0.uint8, 0]: # server_name extension

        echo "server_name"

        if pos + 5 > dataEntry.tlsBytesReceived:
          return true # Invalid fragment, close the connection

        pos += 2 # Skip

        if dataEntry.tlsRecvBuf[pos].uint8 != 0:
          return true # Invalid fragment, close the connection

        inc pos

        let hostnameLen = block:
          var l: uint16
          copyMem(l.addr, dataEntry.tlsRecvBuf[pos].addr, 2)
          nativesockets.htons(l).int

        pos += 2

        if hostnameLen == 0:
          return true # Invalid fragment, close the connection

        if pos + hostnameLen > dataEntry.tlsBytesReceived:
          return true # Invalid fragment, close the connection

        var hostname = newString(hostnameLen)
        copyMem(hostname[0].addr, dataEntry.tlsRecvBuf[pos].addr, hostnameLen)

        pos += hostnameLen

        echo hostname

      elif extensionType == [0.uint8, 5]: # status_request

        echo "status_request"

        if pos + 1 > dataEntry.tlsBytesReceived:
          return true # Invalid fragment, close the connection

        let statusType = dataEntry.tlsRecvBuf[pos].int

        if statusType == 1: # ocsp
          inc pos

          let responderIdListLen = block:
            var l: uint16
            copyMem(l.addr, dataEntry.tlsRecvBuf[pos].addr, 2)
            nativesockets.htons(l).int

          pos += 2

          if responderIdListLen mod 2 != 0:
            return true # Invalid fragment, close the connection

          if pos + responderIdListLen > dataEntry.tlsBytesReceived:
            return true # Invalid fragment, close the connection

          for i in 0 ..< responderIdListLen div 2:
            discard

          pos += responderIdListLen

          let oscpExtensionsLen = block:
            var l: uint16
            copyMem(l.addr, dataEntry.tlsRecvBuf[pos].addr, 2)
            nativesockets.htons(l).int

          pos += 2

          pos += oscpExtensionsLen

        else:

          pos += extensionLen

      elif extensionType == [0.uint8, 10]: # supported_groups

        echo "supported_groups"

        if pos + 2 > dataEntry.tlsBytesReceived:
          return true # Invalid fragment, close the connection

        let curveListBytes = block:
          var l: uint16
          copyMem(l.addr, dataEntry.tlsRecvBuf[pos].addr, 2)
          nativesockets.htons(l).int

        pos += 2

        if curveListBytes mod 2 != 0:
          return true # Invalid fragment, close the connection

        if pos + curveListBytes > dataEntry.tlsBytesReceived:
          return true # Invalid fragment, close the connection

        var x25519: bool
        for i in 0 ..< curveListBytes div 2:
          if dataEntry.tlsRecvBuf[pos + i * 2].uint8 == 0x0 and
            dataEntry.tlsRecvBuf[pos + i * 2 + 1].uint8 == 0x1D:
            x25519 = true
            break

        echo "x25519: ", x25519

        pos += curveListBytes

      elif extensionType == [0.uint8, 11]: # ec_point_formats

        echo "ec_point_formats"

        if pos + 1 > dataEntry.tlsBytesReceived:
          return true # Invalid fragment, close the connection

        let formatTypeBytes = dataEntry.tlsRecvBuf[pos].int

        inc pos

        if pos + formatTypeBytes > dataEntry.tlsBytesReceived:
          return true # Invalid fragment, close the connection

        pos += formatTypeBytes

      elif extensionType == [0.uint8, 13]: # signature_algorithms

        echo "signature_algorithms"

        if pos + 2 > dataEntry.tlsBytesReceived:
          return true # Invalid fragment, close the connection

        let algorithmListBytes = block:
          var l: uint16
          copyMem(l.addr, dataEntry.tlsRecvBuf[pos].addr, 2)
          nativesockets.htons(l).int

        pos += 2

        if algorithmListBytes mod 2 != 0:
          return true # Invalid fragment, close the connection

        if pos + algorithmListBytes > dataEntry.tlsBytesReceived:
          return true # Invalid fragment, close the connection

        pos += algorithmListBytes

      elif extensionType == [0.uint8, 16]: # application_layer_protocol_negotiation

        echo "application_layer_protocol_negotiation"

        if pos + 2 > dataEntry.tlsBytesReceived:
          return true # Invalid fragment, close the connection

        let protocolListLen = block:
          var l: uint16
          copyMem(l.addr, dataEntry.tlsRecvBuf[pos].addr, 2)
          nativesockets.htons(l).int

        pos += 2

        if pos + protocolListLen > dataEntry.tlsBytesReceived:
          return true # Invalid fragment, close the connection

        var offset: int
        while true:
          if pos + 1 > dataEntry.tlsBytesReceived:
            return true # Invalid fragment, close the connection

          let entryLen = dataEntry.tlsRecvBuf[pos].int

          inc pos

          if pos + entryLen > dataEntry.tlsBytesReceived:
            return true # Invalid fragment, close the connection

          var entry = newString(entryLen)
          copyMem(entry[0].addr, dataEntry.tlsRecvBuf[pos].addr, entryLen)

          echo entry

          pos += entryLen
          offset += 1 + entryLen

          if offset == protocolListLen:
            break

      elif extensionType == [0.uint8, 21]: # padding

        echo "padding"

        pos += extensionLen

      elif extensionType == [0.uint8, 23]: # extended_master_secret

        echo "extended_master_secret"

        if extensionLen != 0:
          return true # Invalid fragment, close the connection

        pos += extensionLen

      elif extensionType == [0.uint8, 28]: # record_size_limit

        echo "record_size_limit"

        if extensionLen != 2:
          return true # Invalid fragment, close the connection

        let recordSizeLimit = block:
          var l: uint16
          copyMem(l.addr, dataEntry.tlsRecvBuf[pos].addr, 2)
          nativesockets.htons(l).int

        pos += 2

        echo recordSizeLimit

      elif extensionType == [0.uint8, 34]: # delegated_credentials

        echo "delegated_credentials"

        pos += extensionLen

      elif extensionType == [0.uint8, 35]: # session_ticket

        echo "session_ticket"

        pos += extensionLen

      elif extensionType == [0.uint8, 43]: # supported_versions

        echo "supported_versions"

        if pos + 2 > dataEntry.tlsBytesReceived:
          return true # Invalid fragment, close the connection

        let supportedVersionListBytes = dataEntry.tlsRecvBuf[pos].int

        inc pos

        if supportedVersionListBytes mod 2 != 0:
          return true # Invalid fragment, close the connection

        if pos + supportedVersionListBytes > dataEntry.tlsBytesReceived:
          return true # Invalid fragment, close the connection

        var tls13: bool
        for i in 0 ..< supportedVersionListBytes div 2:
          if dataEntry.tlsRecvBuf[pos + i * 2].uint8 == 3 and
            dataEntry.tlsRecvBuf[pos + i * 2 + 1].uint8 == 4:
            tls13 = true
            break

        echo "tls 1.3: ", tls13

        pos += supportedVersionListBytes

      elif extensionType == [0.uint8, 45]: # psk_key_exchange_modes

        echo "psk_key_exchange_modes"

        let modeListLen = dataEntry.tlsRecvBuf[pos].int

        inc pos

        if pos + modeListLen > dataEntry.tlsBytesReceived:
          return true # Invalid fragment, close the connection

        pos += modeListLen

      elif extensionType == [0.uint8, 51]: # key_share

        echo "key_share"

        if pos + 2 > dataEntry.tlsBytesReceived:
          return true # Invalid fragment, close the connection

        let keyShareDataLen = block:
          var l: uint16
          copyMem(l.addr, dataEntry.tlsRecvBuf[pos].addr, 2)
          nativesockets.htons(l).int

        pos += 2

        var
          offset: int
          x25519: bool
        while true:
          if pos + 4 > dataEntry.tlsBytesReceived:
            return true # Invalid fragment, close the connection

          if dataEntry.tlsRecvBuf[pos].uint8 == 0x0 and
            dataEntry.tlsRecvBuf[pos + 1].uint8 == 0x1D:
            x25519 = true

          pos += 2

          let listEntryBytes = block:
            var l: uint16
            copyMem(l.addr, dataEntry.tlsRecvBuf[pos].addr, 2)
            nativesockets.htons(l).int

          pos += 2

          pos += listEntryBytes
          offset += 4 + listEntryBytes

          if offset == keyShareDataLen:
            break

        echo "x25519: ", x25519

      elif extensionType == [255.uint8, 1]: # renegotiation_info

        echo "renegotiation_info"

        if extensionLen != 1:
          return true # Invalid fragment, close the connection

        inc pos

      else:
        echo "HERE!: ", extensionType, " ", extensionLen
        pos += extensionLen

      if pos == dataEntry.tlsBytesReceived:
        break

    echo "DONE"

  of NeedClientKey:
    discard

proc afterRecv(
  server: Server,
  clientSocket: SocketHandle,
  dataEntry: DataEntry
): bool {.raises: [IOSelectorsException].} =
  # If this is a TLS connection, handle that first
  if dataEntry.tls:
    let closeConnection = server.afterRecvTls(clientSocket, dataEntry)
    # If something bad happened bail out
    if closeConnection:
      return true
    # If all is good we continue on to let the unencrypted bytes be handled

  # Have we upgraded this connection to a websocket?
  # If not, treat incoming bytes as part of HTTP requests.
  if dataEntry.upgradedToWebSocket:
    server.afterRecvWebSocket(clientSocket, dataEntry)
  else:
    server.afterRecvHttp(clientSocket, dataEntry)

proc afterSend(
  server: Server,
  clientSocket: SocketHandle,
  dataEntry: DataEntry
): bool {.raises: [IOSelectorsException].} =
  let
    outgoingBuffer = dataEntry.outgoingBuffers.peekFirst()
    totalBytes = outgoingBuffer.buf1.len + outgoingBuffer.buf2.len
  if outgoingBuffer.bytesSent == totalBytes:
    dataEntry.outgoingBuffers.shrink(1)
    if outgoingBuffer.isWebSocketUpgrade:
      let websocket = WebSocket(
        server: server,
        clientSocket: clientSocket
      )
      websocket.postWebSocketUpdate(WebSocketUpdate(event: OpenEvent))

    if outgoingBuffer.isCloseFrame:
      dataEntry.closeFrameSent = true
    if outgoingBuffer.closeConnection:
      return true
  if dataEntry.outgoingBuffers.len == 0:
    server.selector.updateHandle2(clientSocket, {Read})

proc destroy(server: Server, joinThreads: bool) {.raises: [].} =
  server.destroyCalled.store(true, moRelease)
  if server.selector != nil:
    try:
      server.selector.close()
    except:
      discard # Ignore
  for serverSocket in server.serverSockets:
    serverSocket.close()
  for clientSocket in server.clientSockets:
    clientSocket.close()
  when useLockAndCond:
    broadcast(server.taskQueueCond)
  else:
    server.trigger(server.destroyCalledFd)
  if joinThreads:
    joinThreads(server.workerThreads)
    when useLockAndCond:
      deinitLock(server.taskQueueLock)
      deinitCond(server.taskQueueCond)
    else:
      for workerEventFd in server.workerEventFds:
        discard workerEventFd.close()
      discard server.destroyCalledFd.close()
    try:
      server.responseQueued.close()
    except:
      discard # Ignore
    try:
      server.sendQueued.close()
    except:
      discard # Ignore
    try:
      server.shutdown.close()
    except:
      discard # Ignore
    `=destroy`(server[])
    deallocShared(server)
  else:
    # This is not a clean exit, leak to avoid potential segfaults for now
    # The process is likely going to be exiting anyway
    discard

proc loopForever(server: Server) {.raises: [OSError, IOSelectorsException].} =
  var
    readyKeys: array[maxEventsPerSelectLoop, ReadyKey]
    receivedFrom, sentTo, needClosing: seq[SocketHandle]
    encodedResponses: seq[OutgoingBuffer]
    encodedFrames: seq[OutgoingBuffer]
  while true:
    receivedFrom.setLen(0)
    sentTo.setLen(0)
    needClosing.setLen(0)
    encodedResponses.setLen(0)
    encodedFrames.setLen(0)

    let readyCount = server.selector.selectInto(-1, readyKeys)

    var responseQueuedTriggered, sendQueuedTriggered, shutdownTriggered: bool
    for i in 0 ..< readyCount:
      let readyKey = readyKeys[i]
      if User in readyKey.events:
        let eventDataEntry = server.selector.getData(readyKey.fd)
        if eventDataEntry.forEvent == server.responseQueued:
          responseQueuedTriggered = true
        if eventDataEntry.forEvent == server.sendQueued:
          sendQueuedTriggered = true
        elif eventDataEntry.forEvent == server.shutdown:
          shutdownTriggered = true
        else:
          discard

    if responseQueuedTriggered:
      withLock server.responseQueueLock:
        while server.responseQueue.len > 0:
          encodedResponses.add(server.responseQueue.popFirst())

      for encodedResponse in encodedResponses:
        if encodedResponse.clientSocket in server.selector:
          let clientDataEntry =
            server.selector.getData(encodedResponse.clientSocket)

          clientDataEntry.outgoingBuffers.addLast(encodedResponse)
          server.selector.updateHandle2(
            encodedResponse.clientSocket,
            {Read, Write}
          )

          if encodedResponse.isWebSocketUpgrade:
            clientDataEntry.upgradedToWebSocket = true
            let websocket = WebSocket(
              server: server,
              clientSocket: encodedResponse.clientSocket
            )
            var websocketQueue = initDeque[WebSocketUpdate]()
            withLock server.websocketQueuesLock:
              server.websocketQueues[websocket] = move websocketQueue
              server.websocketClaimed[websocket] = false
            if clientDataEntry.bytesReceived > 0:
              # Why have we received bytes when we are upgrading the connection?
              needClosing.add(websocket.clientSocket)
              clientDataEntry.sendsWaitingForUpgrade.setLen(0)
              server.log(
                DebugLevel,
                "Dropped WebSocket, received unexpected bytes after upgrade request"
              )
              continue
            # Are there any sends that were waiting for this response?
            if clientDataEntry.sendsWaitingForUpgrade.len > 0:
              for encodedFrame in clientDataEntry.sendsWaitingForUpgrade:
                if clientDataEntry.closeFrameQueuedAt > 0:
                  discard # Drop this message
                else:
                  clientDataEntry.outgoingBuffers.addLast(encodedFrame)
                  if encodedFrame.isCloseFrame:
                    clientDataEntry.closeFrameQueuedAt = epochTime()
              clientDataEntry.sendsWaitingForUpgrade.setLen(0)
        else:
          server.log(DebugLevel, "Dropped response to disconnected client")

    if sendQueuedTriggered:
      withLock server.sendQueueLock:
        while server.sendQueue.len > 0:
          encodedFrames.add(server.sendQueue.popFirst())

      for encodedFrame in encodedFrames:
        if encodedFrame.clientSocket in server.selector:
          let clientDataEntry =
            server.selector.getData(encodedFrame.clientSocket)

          # Have we sent the upgrade response yet?
          if clientDataEntry.upgradedToWebSocket:
            if clientDataEntry.closeFrameQueuedAt > 0:
              discard # Drop this message
            else:
              clientDataEntry.outgoingBuffers.addLast(encodedFrame)
              if encodedFrame.isCloseFrame:
                clientDataEntry.closeFrameQueuedAt = epochTime()
              server.selector.updateHandle2(
                encodedFrame.clientSocket,
                {Read, Write}
              )
          else:
            # If we haven't, queue this to wait for the upgrade response
            clientDataEntry.sendsWaitingForUpgrade.add(encodedFrame)
        else:
          server.log(DebugLevel, "Dropped message to disconnected client")

    if shutdownTriggered:
      server.destroy(true)
      return

    for i in 0 ..< readyCount:
      let readyKey = readyKeys[i]

      # echo "Socket ready: ", readyKey.fd, " ", readyKey.events

      if Error in readyKey.events:
        needClosing.add(readyKey.fd.SocketHandle)
        continue

      let dataEntry = server.selector.getData(readyKey.fd)

      if Read in readyKey.events:
        if dataEntry.kind == ServerSocketEntry: # New connection to accept
          let (clientSocket, _) =
            when defined(linux) and not defined(nimdoc):
              var
                sockAddr: SockAddr
                addrLen = sizeof(sockAddr).SockLen
              let
                socket =
                  accept4(
                    readyKey.fd.cint,
                    sockAddr.addr,
                    addrLen.addr,
                    SOCK_CLOEXEC or SOCK_NONBLOCK
                  )
                sockAddrStr =
                  try:
                    getAddrString(sockAddr.addr)
                  except:
                    ""
              (socket, sockAddrStr)
            else:
              readyKey.fd.SocketHandle.accept()

          if clientSocket == osInvalidSocket:
            continue

          when not defined(linux):
            # Not needed on linux where we can use SOCK_NONBLOCK
            clientSocket.setBlocking(false)

          server.clientSockets.incl(clientSocket)

          let clientSocketDataEntry = DataEntry(kind: ClientSocketEntry)
          clientSocketDataEntry.port = dataEntry.port
          clientSocketDataEntry.address = dataEntry.address
          clientSocketDataEntry.tls = dataEntry.tls
          if clientSocketDataEntry.tls:
            clientSocketDataEntry.tlsRecvBuf.setLen(initialRecvBufLen)
          clientSocketDataEntry.recvBuf.setLen(initialRecvBufLen)
          server.selector.registerHandle2(
            clientSocket,
            {Read},
            clientSocketDataEntry
          )
        else: # Client socket
          var bytesReceived: int
          if dataEntry.tls:
            # Expand the TLS recv buffer if it is full
            if dataEntry.tlsBytesReceived == dataEntry.tlsRecvBuf.len:
              dataEntry.tlsRecvBuf.setLen(dataEntry.tlsRecvBuf.len * 2)
            bytesReceived = readyKey.fd.SocketHandle.recv(
              dataEntry.tlsRecvBuf[dataEntry.tlsBytesReceived].addr,
              (dataEntry.tlsRecvBuf.len - dataEntry.tlsBytesReceived).cint,
              0
            )
          else:
            # Expand the recv buffer if it is full
            if dataEntry.bytesReceived == dataEntry.recvBuf.len:
              dataEntry.recvBuf.setLen(dataEntry.recvBuf.len * 2)
            bytesReceived = readyKey.fd.SocketHandle.recv(
              dataEntry.recvBuf[dataEntry.bytesReceived].addr,
              (dataEntry.recvBuf.len - dataEntry.bytesReceived).cint,
              0
            )
          if bytesReceived > 0:
            if dataEntry.tls:
              dataEntry.tlsBytesReceived += bytesReceived
            else:
              dataEntry.bytesReceived += bytesReceived
            receivedFrom.add(readyKey.fd.SocketHandle)
          else:
            needClosing.add(readyKey.fd.SocketHandle)
            continue

      if Write in readyKey.events:
        let
          outgoingBuffer = dataEntry.outgoingBuffers.peekFirst()
          bytesSent =
            if outgoingBuffer.bytesSent < outgoingBuffer.buf1.len:
              readyKey.fd.SocketHandle.send(
                outgoingBuffer.buf1[outgoingBuffer.bytesSent].addr,
                (outgoingBuffer.buf1.len - outgoingBuffer.bytesSent).cint,
                0
              )
            else:
              let buf2Pos =
                outgoingBuffer.bytesSent - outgoingBuffer.buf1.len
              readyKey.fd.SocketHandle.send(
                outgoingBuffer.buf2[buf2Pos].addr,
                (outgoingBuffer.buf2.len - buf2Pos).cint,
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
        dataEntry = server.selector.getData(clientSocket)
        needsClosing = server.afterRecv(clientSocket, dataEntry)
      if needsClosing:
        needClosing.add(clientSocket)

    for clientSocket in sentTo:
      if clientSocket in needClosing:
        continue
      let
        dataEntry = server.selector.getData(clientSocket)
        needsClosing = server.afterSend(clientSocket, dataEntry)
      if needsClosing:
        needClosing.add(clientSocket)

    for clientSocket in needClosing:
      let dataEntry = server.selector.getData(clientSocket)
      try:
        server.selector.unregister(clientSocket)
      except:
        # Leaks DataEntry for this socket
        server.log(DebugLevel, "Error unregistering client socket")
      finally:
        clientSocket.close()
        server.clientSockets.excl(clientSocket)
      if dataEntry.upgradedToWebSocket:
        let websocket = WebSocket(server: server, clientSocket: clientSocket)
        if not dataEntry.closeFrameSent:
          var error = WebSocketUpdate(event: ErrorEvent)
          websocket.postWebSocketUpdate(error)
        var close = WebSocketUpdate(event: CloseEvent)
        websocket.postWebSocketUpdate(close)

proc close*(server: Server) {.raises: [], gcsafe.} =
  ## Cleanly stops and deallocates the server.
  ## In-flight request handler calls will be allowed to finish.
  ## No additional handler calls will be dispatched even if they are queued.
  if server.serveCalled.load(moRelaxed):
    server.trigger(server.shutdown)
  else:
    server.destroy(true)

proc serve*(
  server: Server,
  configs: openarray[ServeConfig]
) {.raises: [MummyError].} =
  ## The server will serve on each address:port entry.
  ## If an entry includes a certificate file that address:port will be a
  ## HTTPS server socket. If no certificate is specified the address:port will
  ## be an HTTP server socket.
  ## This call does not return unless server.close() is called from another
  ## thread.

  if server.serveCalled.exchange(true, moAcquire):
    raise newException(MummyError, "Server already serving")

  try:
    for config in configs:
      let serverSocket = createNativeSocket(
        Domain.AF_INET,
        SockType.SOCK_STREAM,
        Protocol.IPPROTO_TCP,
        false
      )
      if serverSocket == osInvalidSocket:
        raiseOSError(osLastError())

      serverSocket.setBlocking(false)
      serverSocket.setSockOptInt(SOL_SOCKET, SO_REUSEADDR, 1)

      let ai = getAddrInfo(
        config.address,
        config.port,
        Domain.AF_INET,
        SockType.SOCK_STREAM,
        Protocol.IPPROTO_TCP,
      )
      try:
        if bindAddr(serverSocket, ai.ai_addr, ai.ai_addrlen.SockLen) < 0:
          raiseOSError(osLastError())
      finally:
        freeAddrInfo(ai)

      if nativesockets.listen(serverSocket, listenBacklogLen) < 0:
        raiseOSError(osLastError())

      server.serverSockets.add(serverSocket)

      let serverSocketData = DataEntry(kind: ServerSocketEntry)
      serverSocketData.port = config.port
      serverSocketData.address = config.address
      serverSocketData.tls = config.certFile != ""
      server.selector.registerHandle2(serverSocket, {Read}, serverSocketData)
  except:
    server.destroy(true)
    raise currentExceptionAsMummyError()

  try:
    server.loopForever()
  except:
    let e = getCurrentException()
    server.log(ErrorLevel, e.msg & "\n" & e.getStackTrace())
    server.destroy(false)
    raise currentExceptionAsMummyError()

proc serve*(
  server: Server,
  port: Port,
  address = "localhost",
  certFile = "",
  keyFile = ""
) {.raises: [MummyError].} =
  ## The server will serve on the address:port. The default address is
  ## localhost.
  ## If a certificate file is specified the address:port will be a
  ## HTTPS server socket. If no certificate is specified the address:port will
  ## be an HTTP server socket.
  ## This call does not return unless server.close() is called from another
  ## thread.
  server.serve([ServeConfig(
    port: port,
    address: address,
    certFile: certFile,
    keyFile: keyFile
  )])

proc newServer*(
  handler: RequestHandler,
  websocketHandler: WebSocketHandler = nil,
  logHandler: LogHandler = nil,
  workerThreads = max(countProcessors() * 10, 1),
  maxHeadersLen = 8 * 1024, # 8 KB
  maxBodyLen = 1024 * 1024, # 1 MB
  maxMessageLen = 64 * 1024 # 64 KB
): Server {.raises: [MummyError].} =
  ## Creates a new HTTP server. The request handler will be called for incoming
  ## HTTP requests. The WebSocket handler will be called for WebSocket events.
  ## Calls to the HTTP, WebSocket and log handlers are made from worker threads.
  ## WebSocket events are dispatched serially per connection. This means your
  ## WebSocket handler must return from a call before the next call will be
  ## dispatched for the same connection.

  if handler == nil:
    raise newException(MummyError, "The request handler must not be nil")

  var workerThreads = workerThreads
  when defined(mummyNoWorkers): # For testing, fuzzing etc
    workerThreads = 0

  result = cast[Server](allocShared0(sizeof(ServerObj)))
  result.handler = handler
  result.websocketHandler = websocketHandler
  result.logHandler = if logHandler != nil: logHandler else: echoLogger
  result.maxHeadersLen = maxHeadersLen
  result.maxBodyLen = maxBodyLen
  result.maxMessageLen = maxMessageLen

  result.workerThreads.setLen(workerThreads)

  # Stuff that can fail
  try:
    result.responseQueued = newSelectEvent()
    result.sendQueued = newSelectEvent()
    result.shutdown = newSelectEvent()

    result.selector = newSelector[DataEntry]()

    let responseQueuedData = DataEntry(kind: EventEntry)
    responseQueuedData.forEvent = result.responseQueued
    result.selector.registerEvent(result.responseQueued, responseQueuedData)

    let sendQueuedData = DataEntry(kind: EventEntry)
    sendQueuedData.forEvent = result.sendQueued
    result.selector.registerEvent(result.sendQueued, sendQueuedData)

    let shutdownData = DataEntry(kind: EventEntry)
    shutdownData.forEvent = result.shutdown
    result.selector.registerEvent(result.shutdown, shutdownData)

    when useLockAndCond:
      initLock(result.taskQueueLock)
      initCond(result.taskQueueCond)
    else:
      result.workerEventFds.setLen(workerThreads)

      for i in 0 ..< workerThreads:
        result.workerEventFds[i] = eventfd(0, O_CLOEXEC or O_NONBLOCK)
        if result.workerEventFds[i] == -1:
          raiseOSError(osLastError())

      result.destroyCalledFd = eventfd(0, O_CLOEXEC or O_NONBLOCK)

    for i in 0 ..< workerThreads:
      createThread(result.workerThreads[i], workerProc, (result, i))
  except:
    result.destroy(true)
    raise currentExceptionAsMummyError()
