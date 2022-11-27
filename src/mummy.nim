import mummy/common, mummy/internal, std/base64, std/cpuinfo, std/deques,
    std/hashes, std/nativesockets, std/os, std/parseutils,
    std/selectors, std/sets, std/sha1, std/strutils, std/tables, std/times,
    zippy, std/atomics

const useLockAndCond = (not defined(linux)) or defined(mummyUseLockAndCond)

when useLockAndCond:
  import std/locks
else:
  import std/epoll, std/posix

  proc eventfd(count: cuint, flags: cint): cint
     {.cdecl, importc: "eventfd", header: "<sys/eventfd.h>".}

  proc trigger*(efd: cint) {.raises: [].} =
    var v: uint64 = 1
    while true:
      let ret = write(efd, v.addr, sizeof(uint64))
      if ret != sizeof(uint64):
        let err = osLastError()
        if err == OSErrorCode(EAGAIN):
          continue
        # TODO: log?
        echo osErrorMsg(err) & " (code: " & $err & ")"
      break

export Port, common

when not defined(gcArc) and not defined(gcOrc):
  {.error: "Using --mm:arc or --mm:orc is required by Mummy.".}

when not compileOption("threads"):
  {.error: "Using --threads:on is required by Mummy.".}

const
  listenBacklogLen = 128
  maxEventsPerSelectLoop = 64
  initialRecvBufferLen = (32 * 1024) - 9 # 8 byte cap field + null terminator

let
  http10 = "HTTP/1.0"
  http11 = "HTTP/1.1"

type
  Request* {.acyclic.} = ref object
    httpVersion*: HttpVersion
    httpMethod*: string
    uri*: string
    headers*: HttpHeaders
    body*: string
    server: Server
    clientSocket: SocketHandle
    id: uint64

  RequestHandler* = proc(request: Request) {.gcsafe.}

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

  WebSocketHandler* = proc(
    websocket: WebSocket,
    event: WebSocketEvent,
    message: Message
  ) {.gcsafe.}

  ServerObj = object
    port*: Port
    address*: string
    handler: RequestHandler
    websocketHandler: WebSocketHandler
    maxHeadersLen, maxBodyLen, maxMessageLen: int
    workerThreads: seq[Thread[Server]]
    socket: SocketHandle
    selector: Selector[HandleData]
    shutdown: SelectEvent
    clientSockets: HashSet[SocketHandle]
    destroyCalled: Atomic[bool]
    nextRequestId: uint64
    when useLockAndCond:
      taskQueueLock: Lock
      taskQueueCond: Cond
      taskQueue: Deque[WorkerTask]
      responseQueued: SelectEvent
      responseQueue: Deque[OutgoingBuffer]
      responseQueueLock: Atomic[bool]
    else:
      taskNum: uint64
      lockShards: int
      epollFd, destroyCalledFd: cint
      taskQueuedFds: seq[cint]
      taskQueueLocks: seq[Atomic[bool]]
      taskQueues: seq[Deque[WorkerTask]]
      responseQueued: seq[SelectEvent]
      responseQueues: seq[Deque[OutgoingBuffer]]
      responseQueueLocks: seq[Atomic[bool]]
    sendQueued: SelectEvent
    sendQueue: Deque[OutgoingBuffer]
    sendQueueLock: Atomic[bool]
    websocketClaimed: Table[WebSocket, bool]
    websocketQueues: Table[WebSocket, Deque[WebSocketUpdate]]
    websocketQueuesLock: Atomic[bool]

  Server* = ptr ServerObj

  WorkerTask = object
    request: Request
    websocket: WebSocket

  HandleData = ref object
    forEvent: SelectEvent
    recvBuffer: string
    bytesReceived: int
    requestState: IncomingRequestState
    frameState: IncomingFrameState
    outgoingBuffers: Deque[OutgoingBuffer]
    closeFrameQueuedAt: float64
    upgradedToWebSocket, closeFrameSent: bool
    sendsWaitingForUpgrade: seq[OutgoingBuffer]

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
    buffer1, buffer2: string
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
  result &= " (" & $request.id & ")"

proc `$`*(websocket: WebSocket): string =
  "WebSocket " & $cast[uint](hash(websocket))

proc hash*(websocket: WebSocket): Hash =
  var h: Hash
  h = h !& hash(websocket.server)
  h = h !& hash(websocket.clientSocket)
  return !$h

# proc pause() {.importc: "__builtin_ia32_pause", cdecl.}

template withLock(lock: var Atomic[bool], body: untyped): untyped =
    # TAS
    while lock.exchange(true, moAcquire): # Until we get the lock
      discard
    try:
      body
    finally:
      lock.store(false, moRelease)
    # # TTAS
    # while true:
    #   if not lock.exchange(true, moAcquire): # If we got the lock
    #     break
    #   while lock.load(moRelaxed): # While still locked
    #     discard # pause()
    # try:
    #   body
    # finally:
    #   lock.store(false, moRelease)

proc headerContainsToken(headers: var HttpHeaders, key, token: string): bool =
  for (k, v) in headers:
    if cmpIgnoreCase(k, key) == 0:
      if ',' in v:
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
        # ^ Does this but with allocations
        # var parts = v.split(",")
        # for part in parts.mitems:
        #   if cmpIgnoreCase(part.strip(), token) == 0:
        #     return true
      else:
        if cmpIgnoreCase(v, token) == 0:
          return true

proc registerHandle2(
  selector: Selector[HandleData],
  socket: SocketHandle,
  events: set[Event],
  data: HandleData
) {.raises: [IOSelectorsException].} =
  try:
    selector.registerHandle(socket, events, data)
  except ValueError: # Why ValueError?
    raise newException(IOSelectorsException, getCurrentExceptionMsg())

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
  while true:
    try:
      event.trigger()
      break
    except IOSelectorsException as e:
      when defined(linux):
        if e.msg.contains($EAGAIN): # Can this be better?
          continue
      # TODO: log?
      echo e.msg

proc workerProc(server: Server) =
  ## The worker threads run the task queue here

  proc runTask(task: WorkerTask) =
    if task.request != nil:
      try:
        server.handler(task.request)
      except:
        # TODO: log?
        echo getCurrentExceptionMsg()
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
            assert false # Notice this when not a release build

        if update == nil:
          break

        try:
          server.websocketHandler(
            task.websocket,
            update.event,
            move update.message
          )
        except:
          # TODO: log?
          echo getCurrentExceptionMsg()

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
    var shard: int # The shard this worker is currently on
    while true:
      var
        task: WorkerTask
        poppedTask: bool
      if server.destroyCalled.load(moRelaxed):
        break
      withLock server.taskQueueLocks[shard]:
        if server.taskQueues[shard].len > 0:
          task = server.taskQueues[shard].popFirst()
          poppedTask = true
      if poppedTask:
        runTask(task)
      else:
        # Wait to be woken up
        var event: EpollEvent
        let n = epoll_wait(server.epollFd, event.addr, 1, -1);
        if n > 0:
          let fd = cast[cint](event.data.u64)
          if fd == server.destroyCalledFd:
            break
          var found: bool
          for i in 0 ..< server.lockShards:
            if server.taskQueuedFds[i] == fd:
              shard = i
              found = true
              break
          if not found:
            assert false # Notice this when not a release build
          var data: uint64 = 0
          let ret = posix.read(fd, data.addr, sizeof(uint64))
          if ret != sizeof(uint64):
            let err = osLastError()
            if err == OSErrorCode(EAGAIN):
              continue
            raiseOSError(err)
          # Thread has woken up, loop back to top and check on task queue
        else:
          assert false # Notice this when not a release build

proc send*(
  websocket: WebSocket,
  data: sink string,
  kind = TextMessage,
) {.raises: [], gcsafe.} =
  var encodedFrame = OutgoingBuffer()
  encodedFrame.clientSocket = websocket.clientSocket

  case kind:
  of TextMessage:
    encodedFrame.buffer1 = encodeFrameHeader(0x1, data.len)
  of BinaryMessage:
    encodedFrame.buffer1 = encodeFrameHeader(0x2, data.len)
  of Ping:
    encodedFrame.buffer1 = encodeFrameHeader(0x9, data.len)
  of Pong:
    encodedFrame.buffer1 = encodeFrameHeader(0xA, data.len)

  encodedFrame.buffer2 = move data

  withLock websocket.server.sendQueueLock:
    websocket.server.sendQueue.addLast(move encodedFrame)

  websocket.server.sendQueued.trigger2()

proc close*(websocket: WebSocket) {.raises: [], gcsafe.} =
  var encodedFrame = OutgoingBuffer()
  encodedFrame.clientSocket = websocket.clientSocket
  encodedFrame.buffer1 = encodeFrameHeader(0x8, 0)
  encodedFrame.isCloseFrame = true

  withLock websocket.server.sendQueueLock:
    websocket.server.sendQueue.addLast(move encodedFrame)

  websocket.server.sendQueued.trigger2()

proc respond*(
  request: Request,
  statusCode: int,
  headers: sink HttpHeaders = newSeq[(string, string)](),
  body: sink string = ""
) {.raises: [], gcsafe.} =
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
  elif request.httpVersion == Http10 or "Connection" notin headers:
    headers["Connection"] = "keep-alive"

  # If the body is big enough to justify compressing and not already compressed
  if body.len > 128 and "Content-Encoding" notin headers:
    if request.headers.headerContainsToken("Accept-Encoding", "gzip"):
      try:
        body = compress(body.cstring, body.len, BestSpeed, dfGzip)
      except:
        # This should never happen since exceptions are only thrown if
        # the data format is invalid or the level is invalid
        # TODO: log?
        return
      headers["Content-Encoding"] = "gzip"
    elif request.headers.headerContainsToken("Accept-Encoding", "deflate"):
      try:
        body = compress(body.cstring, body.len, BestSpeed, dfDeflate)
      except:
        # See gzip
        # TODO: log?
        return
      headers["Content-Encoding"] = "deflate"
    else:
      discard

  headers["Content-Length"] = $body.len

  encodedResponse.buffer1 = encodeHeaders(statusCode, headers)
  if encodedResponse.buffer1.len + body.len < 32 * 1024:
    # There seems to be a harsh penalty on multiple send() calls on Linux
    # with ab -k so just use 1 buffer if the body is small enough
    encodedResponse.buffer1 &= body
  else:
    encodedResponse.buffer2 = move body
  encodedResponse.isWebSocketUpgrade = headers.headerContainsToken(
    "Upgrade",
    "websocket"
  )

  when useLockAndCond:
    withLock request.server.responseQueueLock:
      request.server.responseQueue.addLast(move encodedResponse)
    request.server.responseQueued.trigger2()
  else:
    let shard = request.id mod cast[uint64](request.server.lockShards)
    withLock request.server.responseQueueLocks[shard]:
      request.server.responseQueues[shard].addLast(move encodedResponse)
    request.server.responseQueued[shard].trigger2()

proc upgradeToWebSocket*(
  request: Request
): WebSocket {.raises: [MummyError], gcsafe.} =
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

proc postTask(server: Server, task: WorkerTask) {.raises: [].} =
  when useLockAndCond:
    withLock server.taskQueueLock:
      server.taskQueue.addLast(task)
      signal(server.taskQueueCond)
  else:
    let shard = server.taskNum mod cast[uint64](server.lockShards)
    withLock server.taskQueueLocks[shard]:
      server.taskQueues[shard].addLast(task)
    server.taskQueuedFds[shard].trigger()
    inc server.taskNum

  # try:
  #   server.handler(task.request)
  # except:
  #   echo getCurrentExceptionMsg()

proc postWebSocketUpdate(
  websocket: WebSocket,
  update: WebSocketUpdate
) {.raises: [].} =
  if websocket.server.websocketHandler == nil:
    # TODO: log?
    return

  var needsTask: bool

  withLock websocket.server.websocketQueuesLock:
    try:
      websocket.server.websocketQueues[websocket].addLast(update)
      if not websocket.server.websocketClaimed[websocket]:
        needsTask = true
    except KeyError:
      assert false # Notice this when not a release build

  if needsTask:
    websocket.server.postTask(WorkerTask(websocket: websocket))

proc sendCloseFrame(
  server: Server,
  clientSocket: SocketHandle,
  handleData: HandleData,
  closeConnection: bool
) {.raises: [IOSelectorsException].} =
  let outgoingBuffer = OutgoingBuffer()
  outgoingBuffer.buffer1 = encodeFrameHeader(0x8, 0)
  outgoingBuffer.isCloseFrame = true
  outgoingBuffer.closeConnection = closeConnection
  handleData.outgoingBuffers.addLast(outgoingBuffer)
  handleData.closeFrameQueuedAt = epochTime()
  server.selector.updateHandle2(clientSocket, {Read, Write})

proc afterRecvWebSocket(
  server: Server,
  clientSocket: SocketHandle,
  handleData: HandleData
): bool {.raises: [IOSelectorsException].} =
  if handleData.closeFrameQueuedAt > 0 and
    epochTime() - handleData.closeFrameQueuedAt > 10:
    # The Close frame dance didn't work out, just close the connection
    # TODO: log?
    return true

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

    if opcode == 0 and handleData.frameState.opcode == 0:
      # Per spec, the first frame must have an opcode > 0
      return true # Close the connection

    if handleData.frameState.opcode != 0 and opcode != 0:
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
      payloadLen = nativesockets.htons(l).int
      pos += 2
    else:
      if handleData.bytesReceived < 10:
        return false # Need to receive more bytes
      var l: uint32
      copyMem(l.addr, handleData.recvBuffer[pos + 4].addr, 4)
      payloadLen = nativesockets.htonl(l).int
      pos += 8

    if handleData.frameState.frameLen + payloadLen > server.maxMessageLen:
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

    if handleData.frameState.opcode == 0:
      # This is the first fragment
      handleData.frameState.opcode = opcode

    # Make room in the message buffer for this fragment
    let newFrameLen = handleData.frameState.frameLen + payloadLen
    if handleData.frameState.buffer.len < newFrameLen:
      let newBufferLen = max(handleData.frameState.buffer.len * 2, newFrameLen)
      handleData.frameState.buffer.setLen(newBufferLen)

    if payloadLen > 0:
      # Copy the fragment into the message buffer
      copyMem(
        handleData.frameState.buffer[handleData.frameState.frameLen].addr,
        handleData.recvBuffer[pos].addr,
        payloadLen
      )
      handleData.frameState.frameLen += payloadLen

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
      if handleData.frameState.opcode == 0:
        return true # Invalid frame, close the connection

      # We have a full message

      var message: Message
      message.data = move handleData.frameState.buffer
      message.data.setLen(handleData.frameState.frameLen)

      handleData.frameState = IncomingFrameState()

      case opcode:
      of 0x1: # Text
        message.kind = TextMessage
      of 0x2: # Binary
        message.kind = BinaryMessage
      of 0x8: # Close
        # If we already queued a close, just close the connection
        # This is not quite perfect
        if handleData.closeFrameQueuedAt > 0:
          return true # Close the connection
        # Otherwise send a Close in response then close the connection
        server.sendCloseFrame(clientSocket, handleData, true)
        continue
      of 0x9: # Ping
        message.kind = Ping
      of 0xA: # Pong
        message.kind = Pong
      else:
        # TODO: log?
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
  handleData: HandleData
): Request {.raises: [].} =
  ## Pops the completed HttpRequest from the socket and resets the parse state.
  result = Request()
  result.server = server
  result.clientSocket = clientSocket
  result.id = server.nextRequestId
  result.httpVersion = handleData.requestState.httpVersion
  result.httpMethod = move handleData.requestState.httpMethod
  result.uri = move handleData.requestState.uri
  result.headers = move handleData.requestState.headers
  result.body = move handleData.requestState.body
  result.body.setLen(handleData.requestState.contentLength)
  handleData.requestState = IncomingRequestState()
  inc server.nextRequestId

proc afterRecvHttp(
  server: Server,
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

    var lineNum, lineStart: int
    while lineStart < headersEnd:
      var lineEnd = handleData.recvBuffer.find(
        "\r\n",
        lineStart,
        headersEnd
      )
      if lineEnd == -1:
        lineEnd = headersEnd

      var lineLen = lineEnd - lineStart
      while lineLen > 0 and handleData.recvBuffer[lineStart] in Whitespace:
        inc lineStart
        dec lineLen
      while lineLen > 0 and
        handleData.recvBuffer[lineStart + lineLen - 1] in Whitespace:
        dec lineLen

      if lineNum == 0: # This is the request line
        let space1 = handleData.recvBuffer.find(
          ' ',
          lineStart,
          lineStart + lineLen - 1
        )
        if space1 == -1:
          return true # Invalid request line, close the connection
        handleData.requestState.httpMethod = handleData.recvBuffer[lineStart ..< space1]
        var remainingLen = lineLen - (space1 + 1 - lineStart)
        let space2 = handleData.recvBuffer.find(
          ' ',
          space1 + 1,
          space1 + 1 + remainingLen - 1
        )
        if space2 == -1:
          return true # Invalid request line, close the connection
        handleData.requestState.uri = handleData.recvBuffer[space1 + 1 ..< space2]
        if handleData.recvBuffer.find(
          ' ',
          space2 + 1,
          lineStart + lineLen - 1
        ) != -1:
          return true # Invalid request line, close the connection
        let httpVersionLen = lineLen - (space2 + 1 - lineStart)
        if httpVersionLen != 8:
          return true # Invalid request line, close the connection
        if equalMem(
          handleData.recvBuffer[space2 + 1].addr,
          http11[0].unsafeAddr,
          8
        ):
          handleData.requestState.httpVersion = Http11
        elif equalMem(
          handleData.recvBuffer[space2 + 1].addr,
          http10[0].unsafeAddr,
          8
        ):
          handleData.requestState.httpVersion = Http10
        else:
          return true # Unsupported HTTP version, close the connection
      else: # This is a header
        let splitAt = handleData.recvBuffer.find(
          ':',
          lineStart,
          lineStart + lineLen - 1
        )
        if splitAt == -1:
          # Malformed header, include it for debugging purposes
          var line = handleData.recvBuffer[lineStart ..< lineStart + lineLen]
          handleData.requestState.headers.add((move line, ""))
        else:
          var
            leftStart = lineStart
            leftLen = splitAt - leftStart
            rightStart = splitAt + 1
            rightLen = lineStart + lineLen - rightStart

          while leftLen > 0 and handleData.recvBuffer[leftStart] in Whitespace:
            inc leftStart
            dec leftLen
          while leftLen > 0 and handleData.recvBuffer[leftStart + leftLen - 1] in Whitespace:
            dec leftLen
          while rightLen > 0 and handleData.recvBuffer[rightStart] in Whitespace:
            inc rightStart
            dec rightLen
          while leftLen > 0 and handleData.recvBuffer[rightStart + rightLen - 1] in Whitespace:
            dec rightLen

          handleData.requestState.headers.add((
            handleData.recvBuffer[leftStart ..< leftStart + leftLen],
            handleData.recvBuffer[rightStart ..< rightStart + rightLen]
          ))

      lineStart = lineEnd + 2
      inc lineNum

    # ^ Does this but with way more allocations
    # var
    #   headerLines: seq[string]
    #   nextLineStart: int
    # while true:
    #   let lineEnd = handleData.recvBuffer.find(
    #     "\r\n",
    #     nextLineStart,
    #     headersEnd
    #   )
    #   if lineEnd == -1:
    #     var line = handleData.recvBuffer[nextLineStart ..< headersEnd].strip()
    #     headerLines.add(move line)
    #     break
    #   else:
    #     headerLines.add(handleData.recvBuffer[nextLineStart ..< lineEnd].strip())
    #     nextLineStart = lineEnd + 2

    # let
    #   requestLine = headerLines[0]
    #   requestLineParts = requestLine.split(" ")
    # if requestLineParts.len != 3:
    #   return true # Malformed request line, close the connection

    # handleData.requestState.httpMethod = requestLineParts[0]
    # handleData.requestState.uri = requestLineParts[1]

    # if requestLineParts[2] == "HTTP/1.0":
    #   handleData.requestState.httpVersion = Http10
    # elif requestLineParts[2] == "HTTP/1.1":
    #   handleData.requestState.httpVersion = Http11
    # else:
    #   return true # Unsupported HTTP version, close the connection

    # for i in 1 ..< headerLines.len:
    #   let parts = headerLines[i].split(":")
    #   if parts.len == 2:
    #     handleData.requestState.headers.add((parts[0].strip(), parts[1].strip()))
    #   else:
    #     handleData.requestState.headers.add((headerLines[i], ""))

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
    # We do this so we can hopefully just move the receive buffer at the end
    # instead of always copying a potentially huge body
    let bodyStart = headersEnd + 4
    if handleData.bytesReceived == bodyStart:
      handleData.bytesReceived = 0
    else:
      # This could be optimized away by having [0] be [head] where head can move
      # without having to copy the headers out
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

      # After we know we've seen the end of the chunk length, parse it
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

      if chunkLen == 0: # A chunk of len 0 marks the end of the request body
        let request = server.popRequest(clientSocket, handleData)
        server.postTask(WorkerTask(request: request))
        return false
  else:
    if handleData.requestState.contentLength > server.maxBodyLen:
      return true # Body is too large, close the connection

    if handleData.bytesReceived < handleData.requestState.contentLength:
      return false # Need to receive more bytes

    # We have the entire request body

    # If this request has a body
    if handleData.requestState.contentLength > 0:
      # If the receive buffer only has the body in it, just move it and reset
      # the receive buffer
      if handleData.requestState.contentLength == handleData.bytesReceived:
        handleData.requestState.body = move handleData.recvBuffer
        handleData.recvBuffer.setLen(initialRecvBufferLen)
      else:
        # Copy the body out of the buffer
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

    let request = server.popRequest(clientSocket, handleData)
    server.postTask(WorkerTask(request: request))

proc afterRecv(
  server: Server,
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
  server: Server,
  clientSocket: SocketHandle,
  handleData: HandleData
): bool {.raises: [IOSelectorsException].} =
  let
    outgoingBuffer = handleData.outgoingBuffers.peekFirst()
    totalBytes = outgoingBuffer.buffer1.len + outgoingBuffer.buffer2.len
  if outgoingBuffer.bytesSent == totalBytes:
    handleData.outgoingBuffers.shrink(1)
    if outgoingBuffer.isWebSocketUpgrade:
      let
        websocket = WebSocket(
          server: server,
          clientSocket: clientSocket
        )
        update = WebSocketUpdate(event: OpenEvent)
      websocket.postWebSocketUpdate(update)

    if outgoingBuffer.isCloseFrame:
      handleData.closeFrameSent = true
    if outgoingBuffer.closeConnection:
      return true
  if handleData.outgoingBuffers.len == 0:
    server.selector.updateHandle2(clientSocket, {Read})

proc destroy(server: Server, joinThreads: bool) {.raises: [].} =
  server.destroyCalled.store(true, moRelease)
  if server.selector != nil:
    try:
      server.selector.close()
    except:
      discard # Ignore
  if server.socket.int != 0:
    server.socket.close()
  for clientSocket in server.clientSockets:
    clientSocket.close()
  when useLockAndCond:
    broadcast(server.taskQueueCond)
  else:
    server.destroyCalledFd.trigger()
  if joinThreads:
    joinThreads(server.workerThreads)
    when useLockAndCond:
      deinitLock(server.taskQueueLock)
      deinitCond(server.taskQueueCond)
    else:
      for i in 0 ..< server.lockShards:
        discard server.taskQueuedFds[i].close()
      discard server.epollFd.close()
    when useLockAndCond:
      try:
        server.responseQueued.close()
      except:
        discard # Ignore
    else:
      for i in 0 ..< server.lockShards:
        try:
          server.responseQueued[i].close()
        except:
          discard # Ignore
    try:
      server.sendQueued.close()
    except:
      discard # Ignore
    `=destroy`(server[])
    deallocShared(server)
  else:
    # This is not a clean exit, leak to avoid potential segfaults for now
    # The process is likely going to be exiting anyway
    discard

proc loopForever(
  server: Server,
  port: Port
) {.raises: [OSError, IOSelectorsException].} =
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
        let eventHandleData = server.selector.getData(readyKey.fd)
        when useLockAndCond:
          if eventHandleData.forEvent == server.responseQueued:
            responseQueuedTriggered = true
            continue
        else:
          for i in 0 ..< server.lockShards:
            if eventHandleData.forEvent == server.responseQueued[i]:
              responseQueuedTriggered = true
              withLock server.responseQueueLocks[i]:
                while server.responseQueues[i].len > 0:
                  encodedResponses.add(server.responseQueues[i].popFirst())

        if eventHandleData.forEvent == server.sendQueued:
          sendQueuedTriggered = true
        elif eventHandleData.forEvent == server.shutdown:
          shutdownTriggered = true
        else:
          discard

    if responseQueuedTriggered:
      when useLockAndCond:
        withLock server.responseQueueLock:
          while server.responseQueue.len > 0:
            encodedResponses.add(server.responseQueue.popFirst())
      else:
        discard

      for encodedResponse in encodedResponses:
        if encodedResponse.clientSocket in server.selector:
          let clientHandleData =
            server.selector.getData(encodedResponse.clientSocket)

          clientHandleData.outgoingBuffers.addLast(encodedResponse)
          server.selector.updateHandle2(
            encodedResponse.clientSocket,
            {Read, Write}
          )

          if encodedResponse.isWebSocketUpgrade:
            clientHandleData.upgradedToWebSocket = true
            let websocket = WebSocket(
              server: server,
              clientSocket: encodedResponse.clientSocket
            )
            var websocketQueue = initDeque[WebSocketUpdate]()
            withLock server.websocketQueuesLock:
              server.websocketQueues[websocket] = move websocketQueue
              server.websocketClaimed[websocket] = false
            if clientHandleData.bytesReceived > 0:
              # Why have we received bytes when we are upgrading the connection?
              needClosing.add(websocket.clientSocket)
              clientHandleData.sendsWaitingForUpgrade.setLen(0)
              # TODO: log?
              continue
            # Are there any sends that were waiting for this response?
            if clientHandleData.sendsWaitingForUpgrade.len > 0:
              for encodedFrame in clientHandleData.sendsWaitingForUpgrade:
                if clientHandleData.closeFrameQueuedAt > 0:
                  discard # Drop this message
                  # TODO: log?
                else:
                  clientHandleData.outgoingBuffers.addLast(encodedFrame)
                  if encodedFrame.isCloseFrame:
                    clientHandleData.closeFrameQueuedAt = epochTime()
              clientHandleData.sendsWaitingForUpgrade.setLen(0)
        else:
          discard # TODO: log?

    if sendQueuedTriggered:
      withLock server.sendQueueLock:
        while server.sendQueue.len > 0:
          encodedFrames.add(server.sendQueue.popFirst())

      for encodedFrame in encodedFrames:
        if encodedFrame.clientSocket in server.selector:
          let clientHandleData =
            server.selector.getData(encodedFrame.clientSocket)

          # Have we sent the upgrade response yet?
          if clientHandleData.upgradedToWebSocket:
            if clientHandleData.closeFrameQueuedAt > 0:
              discard # Drop this message
              # TODO: log?
            else:
              clientHandleData.outgoingBuffers.addLast(encodedFrame)
              if encodedFrame.isCloseFrame:
                clientHandleData.closeFrameQueuedAt = epochTime()
              server.selector.updateHandle2(
                encodedFrame.clientSocket,
                {Read, Write}
              )
          else:
            # If we haven't, queue this to wait for the upgrade response
            clientHandleData.sendsWaitingForUpgrade.add(encodedFrame)
        else:
          discard # TODO: log?

    if shutdownTriggered:
      server.destroy(true)
      return

    for i in 0 ..< readyCount:
      let readyKey = readyKeys[i]
      if readyKey.fd == server.socket.int:
        if Read in readyKey.events:
          let (clientSocket, _) = server.socket.accept()
          if clientSocket == osInvalidSocket:
            continue

          clientSocket.setBlocking(false)
          server.clientSockets.incl(clientSocket)

          let handleData = HandleData()
          handleData.recvBuffer.setLen(initialRecvBufferLen)
          server.selector.registerHandle2(clientSocket, {Read}, handleData)
        else:
          assert false # Notice this when not a release build
      else: # Client socket
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
            (handleData.recvBuffer.len - handleData.bytesReceived).cint,
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
                  (outgoingBuffer.buffer1.len - outgoingBuffer.bytesSent).cint,
                  0
                )
              else:
                let buffer2Pos =
                  outgoingBuffer.bytesSent - outgoingBuffer.buffer1.len
                readyKey.fd.SocketHandle.send(
                  outgoingBuffer.buffer2[buffer2Pos].addr,
                  (outgoingBuffer.buffer2.len - buffer2Pos).cint,
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
      let handleData = server.selector.getData(clientSocket)
      try:
        server.selector.unregister(clientSocket)
      except:
        # Leaks HandleData for this socket
        # TODO: log?
        discard
      finally:
        close(clientSocket)
        server.clientSockets.excl(clientSocket)
      if handleData.upgradedToWebSocket:
        let websocket = WebSocket(server: server, clientSocket: clientSocket)
        if not handleData.closeFrameSent:
          let error = WebSocketUpdate(event: ErrorEvent)
          websocket.postWebSocketUpdate(error)
        let close = WebSocketUpdate(event: CloseEvent)
        websocket.postWebSocketUpdate(close)

proc close*(server: Server) {.raises: [], gcsafe.} =
  if server.socket.int != 0:
    server.shutdown.trigger2()
  else:
    server.destroy(true)

proc serve*(
  server: Server,
  port: Port,
  address = "localhost"
) {.raises: [MummyError].} =
  if server.socket.int != 0:
    raise newException(MummyError, "Server already has a socket")

  server.port = port
  server.address = address

  try:
    server.socket = createNativeSocket(
      Domain.AF_INET,
      SockType.SOCK_STREAM,
      Protocol.IPPROTO_TCP,
      false
    )
    if server.socket == osInvalidSocket:
      raiseOSError(osLastError())

    server.socket.setBlocking(false)
    server.socket.setSockOptInt(SOL_SOCKET, SO_REUSEADDR, 1)

    let ai = getAddrInfo(
      address,
      port,
      Domain.AF_INET,
      SockType.SOCK_STREAM,
      Protocol.IPPROTO_TCP
    )
    try:
      if bindAddr(server.socket, ai.ai_addr, ai.ai_addrlen.SockLen) < 0:
        raiseOSError(osLastError())
    finally:
      freeAddrInfo(ai)

    if nativesockets.listen(server.socket, listenBacklogLen) < 0:
      raiseOSError(osLastError())

    server.selector = newSelector[HandleData]()

    server.selector.registerHandle2(server.socket, {Read}, nil)

    when useLockAndCond:
      let responseQueuedData = HandleData()
      responseQueuedData.forEvent = server.responseQueued
      server.selector.registerEvent(server.responseQueued, responseQueuedData)
    else:
      for i in 0 ..< server.lockShards:
        let responseQueuedData = HandleData()
        responseQueuedData.forEvent = server.responseQueued[i]
        server.selector.registerEvent(server.responseQueued[i], responseQueuedData)

    let sendQueuedData = HandleData()
    sendQueuedData.forEvent = server.sendQueued
    server.selector.registerEvent(server.sendQueued, sendQueuedData)

    let shutdownData = HandleData()
    shutdownData.forEvent = server.shutdown
    server.selector.registerEvent(server.shutdown, shutdownData)
  except:
    server.destroy(true)
    raise currentExceptionAsMummyError()

  try:
    server.loopForever(port)
  except:
    server.destroy(false)
    raise currentExceptionAsMummyError()

proc newServer*(
  handler: RequestHandler,
  websocketHandler: WebSocketHandler = nil,
  workerThreads = max(countProcessors() - 1, 1) * 2,
  maxHeadersLen = 8 * 1024, # 8 KB
  maxBodyLen = 1024 * 1024, # 1 MB
  maxMessageLen = 64 * 1024 # 64 KB
): Server {.raises: [MummyError].} =
  if handler == nil:
    raise newException(MummyError, "The request handler must not be nil")

  result = cast[Server](allocShared0(sizeof(ServerObj)))
  result.handler = handler
  result.websocketHandler = websocketHandler
  result.maxHeadersLen = maxHeadersLen
  result.maxBodyLen = maxBodyLen
  result.maxMessageLen = maxMessageLen
  result.workerThreads.setLen(workerThreads)

  # Stuff that can fail
  try:
    result.sendQueued = newSelectEvent()
    result.shutdown = newSelectEvent()

    when useLockAndCond:
      result.responseQueued = newSelectEvent()
      initLock(result.taskQueueLock)
      initCond(result.taskQueueCond)
    else:
      result.lockShards = max(countProcessors() - 1, 1)

      result.epollFd = epoll_create1(O_CLOEXEC)
      if result.epollFd < 0:
        raiseOSError(osLastError())

      result.destroyCalledFd = eventfd(0, O_CLOEXEC or O_NONBLOCK)
      if result.destroyCalledFd == -1:
        raiseOSError(osLastError())
      var destroyCalledEvent: EpollEvent
      destroyCalledEvent.events = EPOLLIN
      destroyCalledEvent.data.u64 = cast[uint64](result.destroyCalledFd)
      if epoll_ctl(
        result.epollFd,
        EPOLL_CTL_ADD,
        result.destroyCalledFd,
        destroyCalledEvent.addr
      ) != 0:
        raiseOSError(osLastError())

      result.taskQueueLocks.setLen(result.lockShards)
      result.taskQueuedFds.setLen(result.lockShards)
      result.taskQueues.setLen(result.lockShards)
      result.responseQueued.setLen(result.lockShards)
      result.responseQueues.setLen(result.lockShards)
      result.responseQueueLocks.setLen(result.lockShards)

      for i in 0 ..< result.lockShards:
        result.taskQueuedFds[i] = eventfd(0, O_CLOEXEC or O_NONBLOCK)
        if result.taskQueuedFds[i] == -1:
          raiseOSError(osLastError())
        var taskQueuedEvent: EpollEvent
        taskQueuedEvent.events = EPOLLIN or EPOLLET
        taskQueuedEvent.data.u64 = cast[uint64](result.taskQueuedFds[i])
        if epoll_ctl(
          result.epollFd,
          EPOLL_CTL_ADD,
          result.taskQueuedFds[i],
          taskQueuedEvent.addr
        ) != 0:
          raiseOSError(osLastError())

        result.responseQueued[i] = newSelectEvent()

    for workerThead in result.workerThreads.mitems:
      createThread(workerThead, workerProc, result)
  except:
    result.destroy(true)
    raise currentExceptionAsMummyError()
