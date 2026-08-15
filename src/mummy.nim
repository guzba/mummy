when not defined(nimdoc):
  when not defined(gcArc) and not defined(gcOrc) and not defined(gcAtomicArc):
    {.error: "Using --mm:arc, --mm:orc or --mm:atomicArc is required by Mummy.".}

when not compileOption("threads"):
  {.error: "Using --threads:on is required by Mummy.".}

import std/[atomics, base64, cpuinfo, times, monotimes]
import std/[options, sets, deques, hashes, tables]
import std/[nativesockets, os, selectors, random]

import webby/[httpheaders, queryparams, urls]
import chroniclers, crunchy, zippy

import ./mummy/common, ./mummy/internal

from std/strutils import find, cmpIgnoreCase, toLowerAscii

when defined(linux):
  when defined(nimdoc):
    # Why am I doing this?
    from std/posix import write, TPollfd, POLLIN, poll, close, EAGAIN, O_CLOEXEC, O_NONBLOCK
  else:
    import std/posix

  let SOCK_NONBLOCK
    {.importc: "SOCK_NONBLOCK", header: "<sys/socket.h>".}: cint

when defined(windows):
  from std/winlean import TCP_NODELAY
  const ipv6OnlyOption = 27 # IPV6_V6ONLY from Winsock2.
elif defined(posix):
  from std/posix import ECONNABORTED, IPV6_V6ONLY, TCP_NODELAY

import std/locks

export Port, common, httpheaders, queryparams

template logSafely(body: untyped) =
  try:
    body
  except Exception:
    discard

const
  whitespace = {' ', '\t'}
  listenBacklogLen = 128
  maxEventsPerSelectLoop = 64
  initialRecvBufLen = (4 * 1024) - 9 # 8 byte cap field + null terminator

let
  http10 = "HTTP/1.0"
  http11 = "HTTP/1.1"

type
  RequestObj* = object
    httpVersion*: HttpVersion ## HTTP version from the request line.
    httpMethod*: string ## HTTP method from the request line.
    uri*: string ## Raw URI from the HTTP request line.
    path*: string ## Decoded request URI path.
    queryParams*: QueryParams ## Decoded request query parameter key-value pairs.
    pathParams*: PathParams ## Router named path parameter key-value pairs.
    headers*: HttpHeaders ## HTTP headers key-value pairs.
    body*: string ## Request body.
    remoteAddress*: string ## Network address of the request sender.
    server: Server
    clientSocket: SocketHandle
    clientId: uint64
    responded: bool

  Request* = ptr RequestObj

  WebSocket* = object
    server: Server
    clientSocket: SocketHandle
    clientId: uint64

  RequestBodyStream* = object ## Identifies one incoming request body stream.
    server: Server
    clientSocket: SocketHandle
    clientId: uint64
    streamId: uint64

  Message* = object
    kind*: MessageKind
    data*: string

  WebSocketEvent* = enum
    OpenEvent, MessageEvent, ErrorEvent, CloseEvent

  RequestBodyEventKind* = enum ## Incoming request body lifecycle event kinds.
    RequestBodyOpen, RequestBodyChunk, RequestBodyEnd, RequestBodyError

  RequestBodyEvent* = object ## One serialized incoming request body event.
    kind*: RequestBodyEventKind ## The lifecycle event kind.
    data*: string ## Decoded body bytes for `RequestBodyChunk`; empty otherwise.

  MessageKind* = enum
    TextMessage, BinaryMessage, Ping, Pong

  RequestHandler* = proc(request: Request) {.gcsafe.}

  WebSocketHandler* = proc(
    websocket: WebSocket,
    event: WebSocketEvent,
    message: Message
  ) {.gcsafe.}

  RequestBodyHandler* = proc(
    request: Request,
    stream: RequestBodyStream,
    event: RequestBodyEvent
  ) {.gcsafe.}
    ## Handles incoming request bodies selected for streaming.
    ##
    ## Calls are serialized per stream and run on worker threads. During
    ## `RequestBodyOpen`, call `accept`, `buffer`, or `reject`. If no decision is
    ## made, Mummy preserves compatibility by buffering the body and later
    ## invoking the ordinary request handler. An accepted stream does not invoke
    ## the ordinary request handler: respond by `RequestBodyEnd` instead. Mummy
    ## sends a 500 response if the end callback returns without one. Returning
    ## from each chunk callback permits the selector thread to read the next
    ## bounded chunk. `RequestBodyError` is terminal and allows sinks to clean up
    ## after a disconnect, protocol error, or server shutdown.

  RequestBodyDecision = enum
    BodyUndecided, BodyBuffered, BodyStreamed, BodyRejected

  RequestBodyUpdate = object
    event: RequestBodyEvent

  RequestBodyState = object
    request: Request
    updates: Deque[RequestBodyUpdate]
    claimed, handlingEvent, terminalQueued: bool
    currentEvent: RequestBodyEventKind
    decision: RequestBodyDecision

  RequestBodyStore = object
    lock: Lock
    cond: Cond
    states: Table[RequestBodyStream, RequestBodyState]

  RequestBodyControlKind = enum
    BodyDecisionReady, BodyChunkHandled, BodyHandlerFinished

  RequestBodyControl = object
    stream: RequestBodyStream
    kind: RequestBodyControlKind
    decision: RequestBodyDecision

  ServerObj = object
    handler: RequestHandler
    websocketHandler: WebSocketHandler
    requestBodyHandler: RequestBodyHandler
    maxHeadersLen, maxBodyLen, maxMessageLen, requestBodyChunkSize: int
    tcpNoDelay: bool
    rand: Rand
    nextRequestBodyStreamId: uint64
    workerThreads: seq[Thread[Server]]
    serving: Atomic[bool]
    destroyCalled, finishingRequestBodies: bool
    listeningSockets: seq[SocketHandle]
    selector: Selector[DataEntry]
    responseQueued, sendQueued, requestBodyControlQueued, shutdown: SelectEvent
    responseQueuedInitialized, sendQueuedInitialized: bool
    requestBodyControlQueuedInitialized, shutdownInitialized: bool
    clientSockets: HashSet[SocketHandle]
    taskQueueLock: Lock
    taskQueueCond: Cond
    taskQueue: Deque[WorkerTask]
    responseQueue: Deque[OutgoingBuffer]
    responseQueueLock: Lock
    sendQueue: Deque[OutgoingBuffer]
    sendQueueLock: Lock
    requestBodyControlQueue: Deque[RequestBodyControl]
    requestBodyControlQueueLock: Lock
    requestBodies: RequestBodyStore
    websocketClaimed: Table[WebSocket, bool]
    websocketQueues: Table[WebSocket, Deque[WebSocketUpdate]]
    websocketQueuesLock: Lock

  Server* = ptr ServerObj

  WorkerTask = object
    request: Request
    websocket: WebSocket
    requestBody: RequestBodyStream

  DataEntryKind = enum
    ServerSocketEntry, ClientSocketEntry, EventEntry

  DataEntry {.acyclic.} = ref object
    case kind: DataEntryKind:
    of ServerSocketEntry:
      discard
    of EventEntry:
      event: SelectEvent
    of ClientSocketEntry:
      clientId: uint64
      remoteAddress: string
      recvBuf: string
      bytesReceived: int
      requestState: IncomingRequestState
      frameState: IncomingFrameState
      outgoingBuffers: Deque[OutgoingBuffer]
      closeFrameQueuedAt: float64
      upgradedToWebSocket, closeFrameSent: bool
      sendsWaitingForUpgrade: seq[OutgoingBuffer]
      readPaused, closeAfterResponse: bool
      requestCounter: int # Incoming request incs, outgoing response decs

  IncomingBodyMode = enum
    IncomingBodyBuffered, IncomingBodyOpening, IncomingBodyStreaming,
    IncomingBodyRejected, IncomingBodyEnding

  IncomingRequestState = object
    headersParsed: bool
    chunked: bool
    loggedUnexpectedData: bool
    contentLength: int
    httpVersion: HttpVersion
    httpMethod: string
    uri: string
    path: string
    queryParams: QueryParams
    headers: HttpHeaders
    body: string
    bodyMode: IncomingBodyMode
    bodyStream: RequestBodyStream
    bodyBytesReceived: int
    chunkBytesRemaining: int
    readingChunkData: bool

  IncomingFrameState = object
    opcode: uint8
    buffer: string
    frameLen: int

  OutgoingBuffer {.acyclic.} = ref object
    clientSocket: SocketHandle
    clientId: uint64
    closeConnection, isWebSocketUpgrade, isCloseFrame: bool
    buffer1, buffer2: string
    bytesSent: int

  WebSocketUpdate = object
    event: WebSocketEvent
    message: Message

proc `$`*(request: Request): string {.gcsafe.} =
  result = request.httpMethod & " " & request.uri & " "
  {.gcsafe.}:
    case request.httpVersion:
    of Http10:
      result &= http10
    else:
      result &= http11
  result &= " (" & $cast[uint](request) & ")"

proc `$`*(websocket: WebSocket): string =
  "WebSocket " & $cast[uint](hash(websocket))

proc `==`*(a, b: RequestBodyStream): bool {.raises: [].} =
  ## Returns whether two handles identify the same incoming request body.
  a.server == b.server and
    a.clientSocket == b.clientSocket and
    a.clientId == b.clientId and
    a.streamId == b.streamId

proc hash*(stream: RequestBodyStream): Hash {.raises: [].} =
  ## Returns a hash suitable for using a request body stream as a table key.
  result = hash(cast[uint](stream.server))
  result = result !& hash(stream.clientSocket)
  result = result !& hash(stream.clientId)
  result = !$ (result !& hash(stream.streamId))

proc `$`*(stream: RequestBodyStream): string {.raises: [].} =
  ## Returns a diagnostic representation of an incoming request body stream.
  "RequestBodyStream " & $cast[uint](hash(stream))

proc chooseRequestBody(
  stream: RequestBodyStream,
  decision: RequestBodyDecision,
  request: var Request
): bool {.raises: [].} =
  if stream.server == nil:
    return false

  withLock stream.server.requestBodies.lock:
    try:
      var state = addr stream.server.requestBodies.states[stream]
      if not state.handlingEvent:
        return false

      case decision
      of BodyBuffered, BodyStreamed:
        if state.currentEvent != RequestBodyOpen or
            state.decision != BodyUndecided:
          return false
      of BodyRejected:
        if state.currentEvent notin {RequestBodyOpen, RequestBodyChunk} or
            state.decision == BodyRejected:
          return false
        state.terminalQueued = true
      of BodyUndecided:
        return false

      state.decision = decision
      request = state.request
      result = true
    except KeyError:
      discard

proc accept*(stream: RequestBodyStream): bool {.raises: [], gcsafe.} =
  ## Selects event-driven delivery for this body.
  ##
  ## This succeeds only during `RequestBodyOpen`. Body data is decoded from HTTP
  ## framing and delivered through serialized `RequestBodyChunk` events.
  var request: Request
  stream.chooseRequestBody(BodyStreamed, request)

proc buffer*(stream: RequestBodyStream): bool {.raises: [], gcsafe.} =
  ## Selects compatibility buffering for this body.
  ##
  ## This succeeds only during `RequestBodyOpen`. After the complete body has
  ## been received, the ordinary request handler is invoked with `request.body`
  ## populated exactly as it is when no request body handler is configured.
  var request: Request
  stream.chooseRequestBody(BodyBuffered, request)

proc headerContainsToken(headers: var HttpHeaders, key, token: string): bool =
  # If a header looks like `Accept-Encoding: gzip,deflate` then we may want to
  # check if the value contains a specific token (in this case gzip or deflate)
  # This proc does a case-insensitive check while avoiding allocations
  for (k, v) in headers:
    if cmpIgnoreCase(k, key) == 0:
      var first = 0
      while first < v.len:
        var comma = v.find(',', start = first)
        if comma == -1:
          comma = v.len
        var len = comma - first
        while len > 0 and v[first] in whitespace:
          inc first
          dec len
        while len > 0 and v[first + len - 1] in whitespace:
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

proc clientEvents(dataEntry: DataEntry): set[Event] {.raises: [].} =
  if not dataEntry.readPaused:
    result.incl(Event.Read)
  if dataEntry.outgoingBuffers.len > 0:
    result.incl(Event.Write)

proc updateClientEvents(
  server: Server,
  clientSocket: SocketHandle,
  dataEntry: DataEntry
) {.raises: [IOSelectorsException].} =
  server.selector.updateHandle2(clientSocket, dataEntry.clientEvents())

proc pauseClientRead(
  server: Server,
  clientSocket: SocketHandle,
  dataEntry: DataEntry
) {.raises: [].} =
  dataEntry.readPaused = true
  try:
    server.updateClientEvents(clientSocket, dataEntry)
  except IOSelectorsException as e:
    logSafely:
      error "Error pausing request body reads",
        clientSocket = cast[uint](clientSocket),
        exception = e.msg

proc triggerEvent(event: SelectEvent) {.raises: [].} =
  try:
    event.trigger()
  except Exception as e:
    let err = osLastError()
    logSafely:
      error "Error triggering event",
        osError = err,
        osErrorMessage = osErrorMsg(err),
        exception = e.msg

proc setNoDelay(socket: SocketHandle) {.raises: [].} =
  try:
    socket.setSockOptInt(Protocol.IPPROTO_TCP.int, TCP_NODELAY.int, 1)
  except Exception as e:
    logSafely:
      error "Error setting TCP_NODELAY", exception = e.msg

proc send*(
  websocket: WebSocket,
  data: sink string,
  kind = TextMessage,
) {.raises: [], gcsafe.} =
  ## Enqueues the message to be sent over the WebSocket connection.

  var encodedFrame = OutgoingBuffer()
  encodedFrame.clientSocket = websocket.clientSocket
  encodedFrame.clientId = websocket.clientId

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

  var queueWasEmpty: bool
  withLock websocket.server.sendQueueLock:
    queueWasEmpty = websocket.server.sendQueue.len == 0
    websocket.server.sendQueue.addLast(move encodedFrame)

  if queueWasEmpty:
    triggerEvent(websocket.server.sendQueued)

proc close*(websocket: WebSocket) {.raises: [], gcsafe.} =
  ## Begins the WebSocket closing handshake.
  ## This does not discard previously queued messages before starting the
  ## closing handshake.
  ## The handshake will only begin after the queued messages are sent.

  var encodedFrame = OutgoingBuffer()
  encodedFrame.clientSocket = websocket.clientSocket
  encodedFrame.clientId = websocket.clientId
  encodedFrame.buffer1 = encodeFrameHeader(0x8, 0)
  encodedFrame.isCloseFrame = true

  var queueWasEmpty: bool
  withLock websocket.server.sendQueueLock:
    queueWasEmpty = websocket.server.sendQueue.len == 0
    websocket.server.sendQueue.addLast(move encodedFrame)

  if queueWasEmpty:
    triggerEvent(websocket.server.sendQueued)

proc respond*(
  request: Request,
  statusCode: int,
  headers: sink HttpHeaders = emptyHttpHeaders(),
  body: sink string = ""
) {.raises: [], gcsafe.} =
  ## Sends the response for the request.
  ## This should usually only be called once per request.

  if request.responded:
    logSafely:
      info "Responding to a request that has already received a non-1xx response",
        request = $request

  var encodedResponse = OutgoingBuffer()
  encodedResponse.clientSocket = request.clientSocket
  encodedResponse.clientId = request.clientId
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
  if body.len > 860 and "Content-Encoding" notin headers:
    if request.headers.headerContainsToken("Accept-Encoding", "gzip"):
      try:
        body = compress(body.cstring, body.len, BestSpeed, dfGzip)
        headers["Content-Encoding"] = "gzip"
      except Exception as e:
        # This should never happen since exceptions are only thrown if
        # the data format is invalid or the level is invalid
        logSafely:
          debug "Unexpected gzip error", exception = e.msg
    elif request.headers.headerContainsToken("Accept-Encoding", "deflate"):
      try:
        body = compress(body.cstring, body.len, BestSpeed, dfDeflate)
        headers["Content-Encoding"] = "deflate"
      except Exception as e:
        # See gzip
        logSafely:
          debug "Unexpected deflate error", exception = e.msg
    else:
      discard

  # This is usually not set by the caller, however it needs to be for HEAD
  # responses where there is a Content-Length but no body
  if "Content-Length" notin headers:
    let shouldAddContentLengthHeader =
      statusCode != 204 and (statusCode < 100 or statusCode >= 200)
    # Do not add a Content-Length header for a 204 or 1xx response
    # See RFC 7230 3.3.2
    if shouldAddContentLengthHeader or body.len > 0:
      headers["Content-Length"] = $body.len

  encodedResponse.buffer1 = encodeHeaders(statusCode, headers)
  if encodedResponse.buffer1.len + body.len < 32 * 1024:
    # There seems to be a harsh penalty on multiple send() calls on Linux
    # so just use 1 buffer if the body is small enough
    encodedResponse.buffer1 &= body
  else:
    encodedResponse.buffer2 = move body
  encodedResponse.isWebSocketUpgrade = headers.headerContainsToken(
    "Upgrade",
    "websocket"
  )

  if statusCode < 100 or statusCode >= 200:
    # Mark if this request has received a non-informational (1xx) response
    request.responded = true

  var queueWasEmpty: bool
  withLock request.server.responseQueueLock:
    queueWasEmpty = request.server.responseQueue.len == 0
    request.server.responseQueue.addLast(move encodedResponse)

  if queueWasEmpty:
    triggerEvent(request.server.responseQueued)

proc reject*(
  stream: RequestBodyStream,
  statusCode = 413,
  headers: sink HttpHeaders = emptyHttpHeaders(),
  body: sink string = ""
): bool {.raises: [], gcsafe.} =
  ## Rejects this request body and sends a response that closes the connection.
  ##
  ## This succeeds during `RequestBodyOpen` or `RequestBodyChunk`. Closing the
  ## connection avoids buffering or draining the remainder of the rejected
  ## body. Previously delivered chunks remain the handler's responsibility.
  var request: Request
  if not stream.chooseRequestBody(BodyRejected, request):
    return false

  if request != nil and not request.responded:
    headers["Connection"] = "close"
    request.respond(statusCode, move headers, move body)
  result = true

proc upgradeToWebSocket*(
  request: Request
): WebSocket {.raises: [MummyError], gcsafe.} =
  ## Upgrades the request to a WebSocket connection. You can immediately start
  ## calling send().
  ## Future updates for this WebSocket will be calls to the websocketHandler
  ## provided to `newServer`. The first event will be onOpen.
  ## Note: if the client disconnects before receiving this upgrade response,
  ## no onOpen event will be received.
  if not request.headers.headerContainsToken("Connection", "Upgrade"):
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

  result = WebSocket(
    server: request.server,
    clientSocket: request.clientSocket,
    clientId: request.clientId
  )

  let hash = sha1(websocketKey & "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")

  var headers: HttpHeaders
  headers["Connection"] = "Upgrade"
  headers["Upgrade"] = "websocket"
  headers["Sec-WebSocket-Accept"] = base64.encode(hash)

  request.respond(101, headers)

proc postTask(server: Server, task: WorkerTask) {.raises: [], gcsafe.}

proc addRequestBodyState(
  server: Server,
  stream: RequestBodyStream,
  request: Request
) {.raises: [].} =
  withLock server.requestBodies.lock:
    server.requestBodies.states[stream] = RequestBodyState(
      request: request,
      updates: initDeque[RequestBodyUpdate]()
    )

proc postRequestBodyUpdate(
  stream: RequestBodyStream,
  update: sink RequestBodyUpdate,
  urgent = false
) {.raises: [], gcsafe.} =
  var needsTask: bool
  withLock stream.server.requestBodies.lock:
    try:
      var state = addr stream.server.requestBodies.states[stream]
      if state.terminalQueued:
        return
      if update.event.kind in {RequestBodyEnd, RequestBodyError}:
        state.terminalQueued = true
      state.updates.addLast(move update)
      if not state.claimed:
        state.claimed = true
        needsTask = true
    except KeyError:
      discard

  if needsTask:
    if urgent:
      withLock stream.server.taskQueueLock:
        stream.server.taskQueue.addFirst(WorkerTask(requestBody: stream))
      signal(stream.server.taskQueueCond)
    else:
      stream.server.postTask(WorkerTask(requestBody: stream))

proc popRequestBodyUpdate(
  server: Server,
  stream: RequestBodyStream,
  update: var RequestBodyUpdate,
  request: var Request
): bool {.raises: [].} =
  withLock server.requestBodies.lock:
    try:
      var state = addr server.requestBodies.states[stream]
      if state.updates.len > 0:
        update = state.updates.popFirst()
        state.handlingEvent = true
        state.currentEvent = update.event.kind
        request = state.request
        return true
      state.claimed = false
    except KeyError:
      discard

proc requestBodyDecision(
  server: Server,
  stream: RequestBodyStream,
  defaultToBuffer: bool
): RequestBodyDecision {.raises: [].} =
  withLock server.requestBodies.lock:
    try:
      var state = addr server.requestBodies.states[stream]
      state.handlingEvent = false
      if defaultToBuffer and state.decision == BodyUndecided:
        state.decision = BodyBuffered
      result = state.decision
    except KeyError:
      discard

proc removeRequestBodyState(
  server: Server,
  stream: RequestBodyStream
): Request {.raises: [].} =
  withLock server.requestBodies.lock:
    try:
      result = server.requestBodies.states[stream].request
      server.requestBodies.states.del(stream)
      broadcast(server.requestBodies.cond)
    except KeyError:
      discard

proc removeRejectedRequestBodyIfIdle(
  server: Server,
  stream: RequestBodyStream
): Request {.raises: [].} =
  withLock server.requestBodies.lock:
    try:
      let state = addr server.requestBodies.states[stream]
      if state.decision == BodyRejected and state.updates.len == 0:
        result = state.request
        server.requestBodies.states.del(stream)
        broadcast(server.requestBodies.cond)
    except KeyError:
      discard

proc postRequestBodyControl(
  server: Server,
  control: sink RequestBodyControl
) {.raises: [].} =
  var queueWasEmpty: bool
  withLock server.requestBodyControlQueueLock:
    queueWasEmpty = server.requestBodyControlQueue.len == 0
    server.requestBodyControlQueue.addLast(move control)
  if queueWasEmpty:
    triggerEvent(server.requestBodyControlQueued)

proc destroyRequest(request: Request) {.raises: [].} =
  if request != nil:
    `=destroy`(request[])
    deallocShared(request)

proc workerProc(server: Server) {.raises: [].} =
  # The worker threads run the task queue here
  let server = server

  proc runTask(task: WorkerTask) =
    if task.request != nil:
      try:
        server.handler(task.request)
      except Exception as e:
        logSafely:
          error "Handler exception",
            request = $task.request,
            exception = e.msg,
            stackTrace = e.getStackTrace()
        if not task.request.responded:
          task.request.respond(500)
      destroyRequest(task.request)
    elif task.websocket.server != nil:
      withLock server.websocketQueuesLock:
        if server.websocketClaimed.getOrDefault(task.websocket, true):
          # If this websocket has been claimed or if it is not present in
          # the table (which indicates it has been closed), skip this task
          return
        # Claim this websocket
        server.websocketClaimed[task.websocket] = true

      while true: # Process the entire websocket queue
        var update: Option[WebSocketUpdate]
        withLock server.websocketQueuesLock:
          try:
            if server.websocketQueues[task.websocket].len > 0:
              update = some(server.websocketQueues[task.websocket].popFirst())
              if update.get.event == CloseEvent:
                server.websocketQueues.del(task.websocket)
                server.websocketClaimed.del(task.websocket)
            else:
              server.websocketClaimed[task.websocket] = false
          except KeyError:
            discard # Not possible

        if not update.isSome:
          break

        try:
          server.websocketHandler(
            task.websocket,
            update.get.event,
            move update.get.message
          )
        except Exception as e:
          logSafely:
            error "WebSocket exception",
              websocket = $task.websocket,
              exception = e.msg,
              stackTrace = e.getStackTrace()

        if update.get.event == CloseEvent:
          break
    else:
      while true:
        var
          update: RequestBodyUpdate
          request: Request
        if not server.popRequestBodyUpdate(task.requestBody, update, request):
          break

        let eventKind = update.event.kind
        var handlerFailed: bool
        try:
          server.requestBodyHandler(request, task.requestBody, move update.event)
        except Exception as e:
          handlerFailed = true
          logSafely:
            error "Request body handler exception",
              request = $request,
              stream = $task.requestBody,
              event = eventKind,
              exception = e.msg,
              stackTrace = e.getStackTrace()

        case eventKind
        of RequestBodyOpen, RequestBodyChunk:
          if handlerFailed:
            discard task.requestBody.reject(statusCode = 500)

          let decision = server.requestBodyDecision(
            task.requestBody,
            defaultToBuffer = eventKind == RequestBodyOpen and not handlerFailed
          )
          server.postRequestBodyControl(RequestBodyControl(
            stream: task.requestBody,
            kind: if eventKind == RequestBodyOpen:
              BodyDecisionReady
            else:
              BodyChunkHandled,
            decision: decision
          ))

          if decision == BodyRejected:
            let rejectedRequest = server.removeRejectedRequestBodyIfIdle(
              task.requestBody
            )
            destroyRequest(rejectedRequest)
        of RequestBodyEnd:
          discard server.requestBodyDecision(
            task.requestBody,
            defaultToBuffer = false
          )
          if request != nil and not request.responded:
            request.respond(500)
          server.postRequestBodyControl(RequestBodyControl(
            stream: task.requestBody,
            kind: BodyHandlerFinished
          ))
          destroyRequest(server.removeRequestBodyState(task.requestBody))
        of RequestBodyError:
          discard server.requestBodyDecision(
            task.requestBody,
            defaultToBuffer = false
          )
          destroyRequest(server.removeRequestBodyState(task.requestBody))

  when defined(mummyCheck22398):
    var loggedExceptionLeak: bool

  while true:
    acquire(server.taskQueueLock)

    while server.taskQueue.len == 0 and not server.destroyCalled:
      wait(server.taskQueueCond, server.taskQueueLock)

    if server.destroyCalled:
      release(server.taskQueueLock)
      return

    let task = server.taskQueue.popFirst()
    let skipDuringShutdown = server.finishingRequestBodies and
      (task.request != nil or task.websocket.server != nil)
    release(server.taskQueueLock)

    if skipDuringShutdown:
      destroyRequest(task.request)
    else:
      runTask(task)

    when defined(mummyCheck22398):
      # https://github.com/nim-lang/Nim/issues/22398
      if not loggedExceptionLeak and getCurrentExceptionMsg() != "":
        logSafely:
          error "Detected leaked exception", exception = getCurrentExceptionMsg()
        loggedExceptionLeak = true

proc postTask(server: Server, task: WorkerTask) {.raises: [], gcsafe.} =
  withLock server.taskQueueLock:
    server.taskQueue.addLast(task)
  signal(server.taskQueueCond)

proc postWebSocketUpdate(
  websocket: WebSocket,
  update: sink WebSocketUpdate
) {.raises: [].} =
  if websocket.server.websocketHandler == nil:
    logSafely:
      debug "WebSocket event but no WebSocket handler",
        websocket = $websocket,
        event = update.event
    return

  var needsTask: bool

  withLock websocket.server.websocketQueuesLock:
    if websocket notin websocket.server.websocketQueues:
      return

    try:
      websocket.server.websocketQueues[websocket].addLast(move update)
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
  outgoingBuffer.clientSocket = clientSocket
  outgoingBuffer.clientId = dataEntry.clientId
  outgoingBuffer.buffer1 = encodeFrameHeader(0x8, 0)
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

    let isControlFrame = opcode in [0x8.uint8, 0x9, 0xA]
    if isControlFrame and not fin:
      # Per spec, control frames must not be fragmented
      return true # Close the connection
    if payloadLen > 125 and isControlFrame:
      # Per spec, control frames are only allowed payloads up to 125 bytes
      return true # Close the connection

    if dataEntry.frameState.frameLen + payloadLen > server.maxMessageLen:
      logSafely:
        debug "Dropped WebSocket message",
          reason = "message too long",
          messageLen = dataEntry.frameState.frameLen + payloadLen,
          maxMessageLen = server.maxMessageLen
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
      moveMem(
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
        logSafely:
          debug "Dropped WebSocket message",
            reason = "invalid opcode",
            opcode = frameOpcode
        return true # Invalid opcode, close the connection

      let
        websocket = WebSocket(
          server: server,
          clientSocket: clientSocket,
          clientId: dataEntry.clientId
        )
        update = WebSocketUpdate(
          event: MessageEvent,
          message: move message
        )
      websocket.postWebSocketUpdate(update)

proc newRequest(
  server: Server,
  clientSocket: SocketHandle,
  dataEntry: DataEntry
): Request {.raises: [].} =
  result = cast[Request](allocShared0(sizeof(RequestObj)))
  result.server = server
  result.clientSocket = clientSocket
  result.clientId = dataEntry.clientId
  result.remoteAddress = dataEntry.remoteAddress
  result.httpVersion = dataEntry.requestState.httpVersion
  result.httpMethod = move dataEntry.requestState.httpMethod
  result.uri = move dataEntry.requestState.uri
  result.path = move dataEntry.requestState.path
  result.queryParams = move dataEntry.requestState.queryParams
  result.headers = move dataEntry.requestState.headers
  inc dataEntry.requestCounter

proc popRequest(
  server: Server,
  clientSocket: SocketHandle,
  dataEntry: DataEntry
): Request {.raises: [].} =
  ## Pops the completed HttpRequest from the socket and resets the parse state.
  if dataEntry.requestState.bodyStream.server == nil:
    result = server.newRequest(clientSocket, dataEntry)
  else:
    result = server.removeRequestBodyState(dataEntry.requestState.bodyStream)

  result.body = move dataEntry.requestState.body
  result.body.setLen(dataEntry.requestState.bodyBytesReceived)
  dataEntry.requestState = IncomingRequestState()
  if dataEntry.bytesReceived > 0:
    logSafely:
      debug "Receive buffer not empty after request",
        clientSocket = cast[uint](clientSocket),
        bytesReceived = dataEntry.bytesReceived

proc beginRequestBodyStream(
  server: Server,
  clientSocket: SocketHandle,
  dataEntry: DataEntry
) {.raises: [].} =
  inc server.nextRequestBodyStreamId
  if server.nextRequestBodyStreamId == 0:
    inc server.nextRequestBodyStreamId

  let stream = RequestBodyStream(
    server: server,
    clientSocket: clientSocket,
    clientId: dataEntry.clientId,
    streamId: server.nextRequestBodyStreamId
  )
  let request = server.newRequest(clientSocket, dataEntry)

  dataEntry.requestState.bodyMode = IncomingBodyOpening
  dataEntry.requestState.bodyStream = stream
  server.addRequestBodyState(stream, request)
  server.pauseClientRead(clientSocket, dataEntry)
  stream.postRequestBodyUpdate(RequestBodyUpdate(
    event: RequestBodyEvent(kind: RequestBodyOpen)
  ))

proc consumeReceivedBytes(dataEntry: DataEntry, count: int) {.raises: [].} =
  let bytesRemaining = dataEntry.bytesReceived - count
  if bytesRemaining > 0:
    moveMem(
      dataEntry.recvBuf[0].addr,
      dataEntry.recvBuf[count].addr,
      bytesRemaining
    )
  dataEntry.bytesReceived = bytesRemaining

proc appendBufferedBody(dataEntry: DataEntry, count: int) {.raises: [].} =
  let newLength = dataEntry.requestState.bodyBytesReceived + count
  if dataEntry.requestState.body.len < newLength:
    dataEntry.requestState.body.setLen(max(
      dataEntry.requestState.body.len * 2,
      newLength
    ))
  if count > 0:
    copyMem(
      dataEntry.requestState.body[
        dataEntry.requestState.bodyBytesReceived
      ].addr,
      dataEntry.recvBuf[0].addr,
      count
    )
  dataEntry.requestState.bodyBytesReceived = newLength
  dataEntry.consumeReceivedBytes(count)

proc postRequestBodyChunk(
  server: Server,
  clientSocket: SocketHandle,
  dataEntry: DataEntry,
  count: int
) {.raises: [].} =
  var data = newString(count)
  if count > 0:
    copyMem(data[0].addr, dataEntry.recvBuf[0].addr, count)
  dataEntry.consumeReceivedBytes(count)
  dataEntry.requestState.bodyBytesReceived += count
  server.pauseClientRead(clientSocket, dataEntry)
  dataEntry.requestState.bodyStream.postRequestBodyUpdate(RequestBodyUpdate(
    event: RequestBodyEvent(kind: RequestBodyChunk, data: move data)
  ))

proc finishStreamingRequestBody(
  server: Server,
  clientSocket: SocketHandle,
  dataEntry: DataEntry
) {.raises: [].} =
  dataEntry.requestState.bodyMode = IncomingBodyEnding
  server.pauseClientRead(clientSocket, dataEntry)
  dataEntry.requestState.bodyStream.postRequestBodyUpdate(RequestBodyUpdate(
    event: RequestBodyEvent(kind: RequestBodyEnd)
  ))

proc afterRecvHttp(
  server: Server,
  clientSocket: SocketHandle,
  dataEntry: DataEntry
): bool {.raises: [].} =
  # We do not expect pipelined requests so log if any new data is received
  # while a request is outstanding
  if dataEntry.requestCounter > 0 and
    not dataEntry.requestState.headersParsed and
    not dataEntry.requestState.loggedUnexpectedData:
    logSafely:
      debug "Received data before the previous request has been responded to",
        clientSocket = cast[uint](clientSocket),
        requestCounter = dataEntry.requestCounter
    dataEntry.requestState.loggedUnexpectedData = true

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
        logSafely:
          debug "Dropped connection",
            reason = "headers too long",
            clientSocket = cast[uint](clientSocket),
            headersLen = dataEntry.bytesReceived,
            maxHeadersLen = server.maxHeadersLen
        return true # Headers too long or malformed, close the connection
      return false # Try again after receiving more bytes

    # We have the headers, now to parse them (avoiding excess allocations)

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
      while lineLen > 0 and dataEntry.recvBuf[lineStart] in whitespace:
        inc lineStart
        dec lineLen
      while lineLen > 0 and
        dataEntry.recvBuf[lineStart + lineLen - 1] in whitespace:
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
        try:
          var url = parseUrl(dataEntry.requestState.uri)
          dataEntry.requestState.path = move url.path
          dataEntry.requestState.queryParams = move url.query
        except Exception as e:
          logSafely:
            debug "Dropped connection",
              reason = "invalid request URI",
              clientSocket = cast[uint](clientSocket),
              uri = dataEntry.requestState.uri,
              exception = e.msg
          return true # Invalid request URI, close the connection
        if dataEntry.recvBuf.find(
          ' ',
          space2 + 1,
          lineStart + lineLen - 1
        ) != -1:
          return true # Invalid request line, close the connection
        let httpVersionLen = lineLen - (space2 + 1 - lineStart)
        if httpVersionLen != 8:
          return true # Invalid request line, close the connection
        {.gcsafe.}:
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
            dataEntry.recvBuf[leftStart] in whitespace:
            inc leftStart
            dec leftLen
          while leftLen > 0 and
            dataEntry.recvBuf[leftStart + leftLen - 1] in whitespace:
            dec leftLen
          while rightLen > 0 and
            dataEntry.recvBuf[rightStart] in whitespace:
            inc rightStart
            dec rightLen
          while leftLen > 0 and
            dataEntry.recvBuf[rightStart + rightLen - 1] in whitespace:
            dec rightLen

          # TODO: Headers must not contain control characters (0-31, 127)

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

    var foundContentLength, foundTransferEncoding: bool
    for (k, v) in dataEntry.requestState.headers:
      if cmpIgnoreCase(k, "Content-Length") == 0:
        if foundContentLength:
          # This is a second Content-Length header, not valid
          return true # Close the connection
        foundContentLength = true
        if dataEntry.requestState.chunked:
          # Found both Transfer-Encoding: chunked and Content-Length headers
          return true # Close the connection
        try:
          dataEntry.requestState.contentLength = strictParseInt(v)
        except Exception as e:
          return true # Parsing Content-Length failed, close the connection
      elif cmpIgnoreCase(k, "Transfer-Encoding") == 0:
        if foundTransferEncoding:
          # This is a second Transfer-Encoding header, not valid
          return true # Close the connection
        foundTransferEncoding = true

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
      # Preferring to copy the headers out to avoid the worst case of copying
      # huge bodies
      moveMem(
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

    if not dataEntry.requestState.chunked and
        dataEntry.requestState.contentLength > server.maxBodyLen:
      logSafely:
        debug "Dropped connection",
          reason = "body too long",
          clientSocket = cast[uint](clientSocket),
          bodyLen = dataEntry.requestState.contentLength,
          maxBodyLen = server.maxBodyLen
      return true

    if server.requestBodyHandler != nil and
        (dataEntry.requestState.chunked or
          dataEntry.requestState.contentLength > 0):
      server.beginRequestBodyStream(clientSocket, dataEntry)
      return false

  # Headers have been parsed, now for the body

  if dataEntry.requestState.bodyMode in {
      IncomingBodyOpening, IncomingBodyRejected, IncomingBodyEnding}:
    return false

  if dataEntry.requestState.chunked:
    while true:
      if not dataEntry.requestState.readingChunkData:
        if dataEntry.bytesReceived < 3:
          return false

        let chunkLenEnd = dataEntry.recvBuf.find(
          "\r\n",
          0,
          min(dataEntry.bytesReceived - 1, 19)
        )
        if chunkLenEnd < 0:
          if dataEntry.bytesReceived > 19:
            return true
          return false

        var chunkLen: int
        try:
          chunkLen = strictParseHex(
            dataEntry.recvBuf.toOpenArray(0, chunkLenEnd - 1)
          )
        except Exception:
          return true

        if chunkLen > server.maxBodyLen -
            dataEntry.requestState.bodyBytesReceived:
          logSafely:
            debug "Dropped connection",
              reason = "body too long",
              clientSocket = cast[uint](clientSocket),
              bodyBytesReceived = dataEntry.requestState.bodyBytesReceived,
              nextChunkLen = chunkLen,
              maxBodyLen = server.maxBodyLen
          return true

        dataEntry.consumeReceivedBytes(chunkLenEnd + 2)
        if chunkLen == 0:
          if dataEntry.bytesReceived < 2:
            return false
          if dataEntry.recvBuf[0] != '\r' or dataEntry.recvBuf[1] != '\n':
            return true
          dataEntry.consumeReceivedBytes(2)
          if dataEntry.requestState.bodyMode == IncomingBodyStreaming:
            server.finishStreamingRequestBody(clientSocket, dataEntry)
          else:
            let request = server.popRequest(clientSocket, dataEntry)
            server.postTask(WorkerTask(request: request))
          return false

        dataEntry.requestState.chunkBytesRemaining = chunkLen
        dataEntry.requestState.readingChunkData = true

      if dataEntry.requestState.chunkBytesRemaining == 0:
        if dataEntry.bytesReceived < 2:
          return false
        if dataEntry.recvBuf[0] != '\r' or dataEntry.recvBuf[1] != '\n':
          return true
        dataEntry.consumeReceivedBytes(2)
        dataEntry.requestState.readingChunkData = false
      elif dataEntry.bytesReceived == 0:
        return false
      else:
        var count = min(
          dataEntry.requestState.chunkBytesRemaining,
          dataEntry.bytesReceived
        )
        if dataEntry.requestState.bodyMode == IncomingBodyStreaming:
          count = min(count, server.requestBodyChunkSize)
          dataEntry.requestState.chunkBytesRemaining -= count
          server.postRequestBodyChunk(clientSocket, dataEntry, count)
          return false

        dataEntry.requestState.chunkBytesRemaining -= count
        dataEntry.appendBufferedBody(count)
  elif dataEntry.requestState.bodyMode == IncomingBodyStreaming:
    let bytesRemaining = dataEntry.requestState.contentLength -
      dataEntry.requestState.bodyBytesReceived
    if bytesRemaining == 0:
      server.finishStreamingRequestBody(clientSocket, dataEntry)
    elif dataEntry.bytesReceived > 0:
      let count = min(
        min(bytesRemaining, dataEntry.bytesReceived),
        server.requestBodyChunkSize
      )
      server.postRequestBodyChunk(clientSocket, dataEntry, count)
    return false
  else:
    if dataEntry.bytesReceived < dataEntry.requestState.contentLength:
      return false

    if dataEntry.requestState.contentLength > 0:
      if dataEntry.requestState.contentLength == dataEntry.bytesReceived:
        dataEntry.requestState.body = move dataEntry.recvBuf
        dataEntry.recvBuf.setLen(initialRecvBufLen)
        dataEntry.bytesReceived = 0
      else:
        dataEntry.requestState.body.setLen(dataEntry.requestState.contentLength)
        copyMem(
          dataEntry.requestState.body[0].addr,
          dataEntry.recvBuf[0].addr,
          dataEntry.requestState.contentLength
        )
        dataEntry.consumeReceivedBytes(dataEntry.requestState.contentLength)
      dataEntry.requestState.bodyBytesReceived =
        dataEntry.requestState.contentLength

    let request = server.popRequest(clientSocket, dataEntry)
    server.postTask(WorkerTask(request: request))

proc afterRecv(
  server: Server,
  clientSocket: SocketHandle,
  dataEntry: DataEntry
): bool {.raises: [IOSelectorsException].} =
  # Have we upgraded this connection to a websocket?
  # If not, treat incoming bytes as part of HTTP requests.
  if dataEntry.upgradedToWebSocket:
    server.afterRecvWebSocket(clientSocket, dataEntry)
  else:
    server.afterRecvHttp(clientSocket, dataEntry)

proc resumeRequestBody(
  server: Server,
  clientSocket: SocketHandle,
  dataEntry: DataEntry
): bool {.raises: [IOSelectorsException].} =
  dataEntry.readPaused = false
  result = server.afterRecvHttp(clientSocket, dataEntry)
  if not result and not dataEntry.readPaused:
    server.updateClientEvents(clientSocket, dataEntry)

proc processRequestBodyControl(
  server: Server,
  control: RequestBodyControl,
  dataEntry: DataEntry
): bool {.raises: [IOSelectorsException].} =
  if dataEntry.requestState.bodyStream != control.stream:
    return false

  template stopRejectedBody() =
    dataEntry.requestState.bodyMode = IncomingBodyRejected
    dataEntry.readPaused = true
    dataEntry.closeAfterResponse = true
    server.updateClientEvents(control.stream.clientSocket, dataEntry)
    result = dataEntry.requestCounter == 0 and
      dataEntry.outgoingBuffers.len == 0

  case control.kind
  of BodyDecisionReady:
    if dataEntry.requestState.bodyMode != IncomingBodyOpening:
      return false
    case control.decision
    of BodyBuffered:
      dataEntry.requestState.bodyMode = IncomingBodyBuffered
      result = server.resumeRequestBody(control.stream.clientSocket, dataEntry)
    of BodyStreamed:
      dataEntry.requestState.bodyMode = IncomingBodyStreaming
      result = server.resumeRequestBody(control.stream.clientSocket, dataEntry)
    of BodyRejected, BodyUndecided:
      stopRejectedBody()
  of BodyChunkHandled:
    if dataEntry.requestState.bodyMode != IncomingBodyStreaming:
      return false
    if control.decision == BodyRejected:
      stopRejectedBody()
    else:
      result = server.resumeRequestBody(control.stream.clientSocket, dataEntry)
  of BodyHandlerFinished:
    if dataEntry.requestState.bodyMode == IncomingBodyEnding:
      dataEntry.requestState = IncomingRequestState()
      dataEntry.readPaused = false
      server.updateClientEvents(control.stream.clientSocket, dataEntry)
      if dataEntry.bytesReceived > 0:
        logSafely:
          debug "Receive buffer not empty after streamed request",
            clientSocket = cast[uint](control.stream.clientSocket),
            bytesReceived = dataEntry.bytesReceived

proc afterSend(
  server: Server,
  clientSocket: SocketHandle,
  dataEntry: DataEntry
): bool {.raises: [IOSelectorsException].} =
  let
    outgoingBuffer = dataEntry.outgoingBuffers.peekFirst()
    totalBytes = outgoingBuffer.buffer1.len + outgoingBuffer.buffer2.len
  if outgoingBuffer.bytesSent == totalBytes:
    # The current outgoing buffer for this socket has been fully sent
    # Remove it from the outgoing buffer queue
    dataEntry.outgoingBuffers.shrink(fromFirst = 1)
    if outgoingBuffer.isCloseFrame:
      dataEntry.closeFrameSent = true
    if outgoingBuffer.closeConnection:
      return true
  # If we don't have any more outgoing buffers, update the selector
  if dataEntry.outgoingBuffers.len == 0:
    if dataEntry.closeAfterResponse:
      return true
    server.updateClientEvents(clientSocket, dataEntry)

proc acceptClient(
  listeningSocket: SocketHandle
): (SocketHandle, string) {.raises: [OSError].} =
  var
    peerAddress: Sockaddr_storage
    peerAddressLen = sizeof(peerAddress).SockLen

  let clientSocket =
    when defined(linux) and not defined(nimdoc):
      accept4(
        listeningSocket,
        cast[ptr SockAddr](addr peerAddress),
        addr peerAddressLen,
        SOCK_CLOEXEC or SOCK_NONBLOCK
      )
    else:
      nativesockets.accept(
        listeningSocket,
        cast[ptr SockAddr](addr peerAddress),
        addr peerAddressLen
      )

  if clientSocket == osInvalidSocket:
    return (clientSocket, "")

  when not defined(linux):
    when declared(setInheritable):
      if not clientSocket.setInheritable(false):
        let error = osLastError()
        clientSocket.close()
        raiseOSError(error)

  let remoteAddress =
    try:
      getAddrString(cast[ptr SockAddr](addr peerAddress))
    except Exception:
      ""

  (clientSocket, remoteAddress)

proc isTransientAcceptError(error: OSErrorCode): bool =
  when defined(nimdoc):
    false
  elif defined(windows):
    error.int32 in [WSAEWOULDBLOCK, WSAECONNRESET, WSAECONNABORTED]
  else:
    error.int32 in [EAGAIN, EWOULDBLOCK, EINTR, ECONNABORTED]

proc abortRequestBodies(server: Server) {.raises: [], gcsafe.} =
  var streams: seq[RequestBodyStream]
  withLock server.requestBodies.lock:
    for stream in server.requestBodies.states.keys:
      streams.add(stream)

  if server.workerThreads.len == 0:
    var requests: seq[Request]
    withLock server.requestBodies.lock:
      for state in server.requestBodies.states.values:
        requests.add(state.request)
      server.requestBodies.states.clear()
      broadcast(server.requestBodies.cond)
    for request in requests:
      destroyRequest(request)
    return

  for stream in streams:
    stream.postRequestBodyUpdate(
      RequestBodyUpdate(event: RequestBodyEvent(kind: RequestBodyError)),
      urgent = true
    )

  acquire(server.requestBodies.lock)
  while server.requestBodies.states.len > 0:
    wait(server.requestBodies.cond, server.requestBodies.lock)
  release(server.requestBodies.lock)

proc destroy(server: Server, joinThreads: bool) {.raises: [], gcsafe.} =
  if joinThreads:
    withLock server.taskQueueLock:
      server.finishingRequestBodies = true
  for listeningSocket in server.listeningSockets:
    listeningSocket.close()
  for clientSocket in server.clientSockets:
    clientSocket.close()
  if joinThreads:
    server.abortRequestBodies()
  withLock server.taskQueueLock:
    server.destroyCalled = true
  if server.selector != nil:
    try:
      server.selector.close()
    except Exception as e:
      discard # Ignore
  broadcast(server.taskQueueCond)
  if joinThreads:
    joinThreads(server.workerThreads)
    deinitLock(server.taskQueueLock)
    deinitCond(server.taskQueueCond)
    deinitLock(server.responseQueueLock)
    deinitLock(server.sendQueueLock)
    deinitLock(server.requestBodyControlQueueLock)
    deinitLock(server.requestBodies.lock)
    deinitCond(server.requestBodies.cond)
    deinitLock(server.websocketQueuesLock)
    if server.responseQueuedInitialized:
      try:
        server.responseQueued.close()
      except Exception as e:
        discard # Ignore
    if server.sendQueuedInitialized:
      try:
        server.sendQueued.close()
      except Exception as e:
        discard # Ignore
    if server.requestBodyControlQueuedInitialized:
      try:
        server.requestBodyControlQueued.close()
      except Exception as e:
        discard # Ignore
    if server.shutdownInitialized:
      try:
        server.shutdown.close()
      except Exception as e:
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
    receivedFrom, sentTo: seq[SocketHandle]
    needClosing: HashSet[SocketHandle]
    encodedResponses: seq[OutgoingBuffer]
    encodedFrames: seq[OutgoingBuffer]
    requestBodyControls: seq[RequestBodyControl]
  while true:
    receivedFrom.setLen(0)
    sentTo.setLen(0)
    needClosing.clear()
    encodedResponses.setLen(0)
    encodedFrames.setLen(0)
    requestBodyControls.setLen(0)

    let readyCount = server.selector.selectInto(-1, readyKeys)

    # Collapse these events into simple flags
    var
      responseQueuedTriggered, sendQueuedTriggered: bool
      requestBodyControlQueuedTriggered, shutdownTriggered: bool
    for i in 0 ..< readyCount:
      let readyKey = readyKeys[i]
      if User in readyKey.events:
        let eventDataEntry = server.selector.getData(readyKey.fd)
        if eventDataEntry.event == server.responseQueued:
          responseQueuedTriggered = true
        elif eventDataEntry.event == server.sendQueued:
          sendQueuedTriggered = true
        elif eventDataEntry.event == server.requestBodyControlQueued:
          requestBodyControlQueuedTriggered = true
        elif eventDataEntry.event == server.shutdown:
          shutdownTriggered = true
        else:
          discard

    if requestBodyControlQueuedTriggered:
      withLock server.requestBodyControlQueueLock:
        while server.requestBodyControlQueue.len > 0:
          requestBodyControls.add(server.requestBodyControlQueue.popFirst())

      for control in requestBodyControls:
        let clientSocket = control.stream.clientSocket
        if clientSocket in server.selector:
          let dataEntry = server.selector.getData(clientSocket)
          if dataEntry.kind == ClientSocketEntry and
              dataEntry.clientId == control.stream.clientId:
            if server.processRequestBodyControl(control, dataEntry):
              needClosing.incl(clientSocket)

    if responseQueuedTriggered:
      # If we have responses queued move them to the outgoing buffer queue of
      # the appropriate socket and update the socket selector to include Write

      withLock server.responseQueueLock:
        while server.responseQueue.len > 0:
          encodedResponses.add(server.responseQueue.popFirst())

      for encodedResponse in encodedResponses:
        if encodedResponse.clientSocket in server.selector:
          let clientDataEntry =
            server.selector.getData(encodedResponse.clientSocket)
          if encodedResponse.clientId == clientDataEntry.clientId:
            clientDataEntry.outgoingBuffers.addLast(encodedResponse)
            server.updateClientEvents(
              encodedResponse.clientSocket,
              clientDataEntry
            )

            clientDataEntry.requestCounter =
              max(clientDataEntry.requestCounter - 1, 0)

            if encodedResponse.isWebSocketUpgrade:
              clientDataEntry.upgradedToWebSocket = true
              let websocket = WebSocket(
                server: server,
                clientSocket: encodedResponse.clientSocket,
                clientId: encodedResponse.clientId
              )
              withLock server.websocketQueuesLock:
                server.websocketQueues[websocket] = initDeque[WebSocketUpdate]()
                server.websocketClaimed[websocket] = false
              websocket.postWebSocketUpdate(WebSocketUpdate(event: OpenEvent))
              # Are there any sends that were waiting for this response?
              if clientDataEntry.sendsWaitingForUpgrade.len > 0:
                for encodedFrame in clientDataEntry.sendsWaitingForUpgrade:
                  if clientDataEntry.closeFrameQueuedAt > 0:
                    logSafely:
                      debug "Dropped WebSocket message",
                        reason = "connection closing",
                        clientSocket = cast[uint](encodedFrame.clientSocket)
                  else:
                    clientDataEntry.outgoingBuffers.addLast(encodedFrame)
                    if encodedFrame.isCloseFrame:
                      clientDataEntry.closeFrameQueuedAt = epochTime()
                clientDataEntry.sendsWaitingForUpgrade.setLen(0)
          else:
            # Was this file descriptor reused for a different client?
            logSafely:
              debug "Dropped response",
                reason = "client disconnected",
                clientSocket = cast[uint](encodedResponse.clientSocket)
        else:
          logSafely:
            debug "Dropped response",
              reason = "client disconnected",
              clientSocket = cast[uint](encodedResponse.clientSocket)

    if sendQueuedTriggered:
      # If we have any sends queued move them to the outgoing buffer queue of
      # the appropriate socket and update the socket selector to include Write

      withLock server.sendQueueLock:
        while server.sendQueue.len > 0:
          encodedFrames.add(server.sendQueue.popFirst())

      for encodedFrame in encodedFrames:
        if encodedFrame.clientSocket in server.selector:
          let clientDataEntry =
            server.selector.getData(encodedFrame.clientSocket)
          if encodedFrame.clientId == clientDataEntry.clientId:
            # Have we sent the upgrade response yet?
            if clientDataEntry.upgradedToWebSocket:
              if clientDataEntry.closeFrameQueuedAt > 0:
                logSafely:
                  debug "Dropped WebSocket message",
                    reason = "connection closing",
                    clientSocket = cast[uint](encodedFrame.clientSocket)
              else:
                clientDataEntry.outgoingBuffers.addLast(encodedFrame)
                if encodedFrame.isCloseFrame:
                  clientDataEntry.closeFrameQueuedAt = epochTime()
                server.updateClientEvents(
                  encodedFrame.clientSocket,
                  clientDataEntry
                )
            else:
              # If we haven't, queue this to wait for the upgrade response
              clientDataEntry.sendsWaitingForUpgrade.add(encodedFrame)
          else:
            # Was this file descriptor reused for a different client?
            logSafely:
              debug "Dropped WebSocket message",
                reason = "client disconnected",
                clientSocket = cast[uint](encodedFrame.clientSocket)
        else:
          logSafely:
            debug "Dropped WebSocket message",
              reason = "client disconnected",
              clientSocket = cast[uint](encodedFrame.clientSocket)

    if shutdownTriggered:
      server.destroy(true)
      return

    # This is the main client socket select loop
    for i in 0 ..< readyCount:
      let readyKey = readyKeys[i]

      # echo "Socket ready: ", readyKey.fd, " ", readyKey.events

      let readyDataEntry = server.selector.getData(readyKey.fd)
      if readyDataEntry.kind == ServerSocketEntry:
        # We should have a new client socket to accept
        if Read in readyKey.events:
          let listeningSocket = readyKey.fd.SocketHandle
          let (clientSocket, remoteAddress) =
            acceptClient(listeningSocket)

          if clientSocket == osInvalidSocket:
            let error = osLastError()
            if not isTransientAcceptError(error):
              raiseOSError(error)
          else:
            when not defined(linux):
              # Not needed on linux where we use SOCK_NONBLOCK.
              clientSocket.setBlocking(false)

            if server.tcpNoDelay:
              setNoDelay(clientSocket)

            server.clientSockets.incl(clientSocket)

            let dataEntry = DataEntry(kind: ClientSocketEntry)
            dataEntry.clientId = server.rand.next()
            dataEntry.remoteAddress = remoteAddress
            dataEntry.recvBuf.setLen(initialRecvBufLen)
            server.selector.registerHandle2(clientSocket, {Read}, dataEntry)
      elif readyDataEntry.kind == ClientSocketEntry:
        if Event.Error in readyKey.events:
          needClosing.incl(readyKey.fd.SocketHandle)
          continue

        let dataEntry = readyDataEntry

        if Read in readyKey.events and not dataEntry.readPaused:
          # Expand the buffer if it is full
          if dataEntry.bytesReceived == dataEntry.recvBuf.len:
            dataEntry.recvBuf.setLen(dataEntry.recvBuf.len * 2)

          let bytesReceived = readyKey.fd.SocketHandle.recv(
            dataEntry.recvBuf[dataEntry.bytesReceived].addr,
            (dataEntry.recvBuf.len - dataEntry.bytesReceived).cint,
            0
          )
          if bytesReceived > 0:
            dataEntry.bytesReceived += bytesReceived
            receivedFrom.add(readyKey.fd.SocketHandle)
          else:
            needClosing.incl(readyKey.fd.SocketHandle)
            continue

        if Write in readyKey.events:
          let
            outgoingBuffer = dataEntry.outgoingBuffers.peekFirst()
            bytesSent =
              if outgoingBuffer.bytesSent < outgoingBuffer.buffer1.len:
                readyKey.fd.SocketHandle.send(
                  outgoingBuffer.buffer1[outgoingBuffer.bytesSent].addr,
                  (outgoingBuffer.buffer1.len - outgoingBuffer.bytesSent).cint,
                  when defined(MSG_NOSIGNAL): MSG_NOSIGNAL else: 0
                )
              else:
                let buffer2Pos =
                  outgoingBuffer.bytesSent - outgoingBuffer.buffer1.len
                readyKey.fd.SocketHandle.send(
                  outgoingBuffer.buffer2[buffer2Pos].addr,
                  (outgoingBuffer.buffer2.len - buffer2Pos).cint,
                  when defined(MSG_NOSIGNAL): MSG_NOSIGNAL else: 0
                )
          if bytesSent > 0:
            outgoingBuffer.bytesSent += bytesSent
            sentTo.add(readyKey.fd.SocketHandle)
          else:
            needClosing.incl(readyKey.fd.SocketHandle)
            continue

    for clientSocket in receivedFrom:
      if clientSocket in needClosing:
        continue
      let
        dataEntry = server.selector.getData(clientSocket)
        needsClosing = server.afterRecv(clientSocket, dataEntry)
      if needsClosing:
        needClosing.incl(clientSocket)

    for clientSocket in sentTo:
      if clientSocket in needClosing:
        continue
      let
        dataEntry = server.selector.getData(clientSocket)
        needsClosing = server.afterSend(clientSocket, dataEntry)
      if needsClosing:
        needClosing.incl(clientSocket)

    for clientSocket in needClosing:
      let dataEntry = server.selector.getData(clientSocket)
      try:
        server.selector.unregister(clientSocket)
      except Exception as e:
        # Leaks DataEntry for this socket
        logSafely:
          debug "Error unregistering client socket",
            clientSocket = cast[uint](clientSocket),
            exception = e.msg
      finally:
        clientSocket.close()
        server.clientSockets.excl(clientSocket)
      if dataEntry.upgradedToWebSocket:
        let websocket = WebSocket(
          server: server,
          clientSocket: clientSocket,
          clientId: dataEntry.clientId
        )
        if not dataEntry.closeFrameSent:
          var error = WebSocketUpdate(event: ErrorEvent)
          websocket.postWebSocketUpdate(error)
        var close = WebSocketUpdate(event: CloseEvent)
        websocket.postWebSocketUpdate(close)
      if dataEntry.requestState.bodyStream.server != nil:
        dataEntry.requestState.bodyStream.postRequestBodyUpdate(
          RequestBodyUpdate(event: RequestBodyEvent(kind: RequestBodyError)),
          urgent = true
        )

proc close*(server: Server) {.raises: [], gcsafe.} =
  ## Cleanly stops and deallocates the server.
  ## In-flight handler calls are allowed to finish. Active request body streams
  ## receive their terminal event so handlers can release resources. No queued
  ## ordinary request or WebSocket handler calls are newly dispatched.
  if server.listeningSockets.len > 0:
    triggerEvent(server.shutdown)
  else:
    server.destroy(true)

proc createListeningSocket(
  address: string,
  port: Port,
  domain: Domain,
  ipv6Only: bool
): SocketHandle =
  let aiList = getAddrInfo(
    address,
    port,
    domain,
    SockType.SOCK_STREAM,
    Protocol.IPPROTO_TCP,
  )
  try:
    var
      ai = aiList
      lastError = default(OSErrorCode)
    while ai != nil:
      let listeningSocket = createNativeSocket(
        ai.ai_family,
        ai.ai_socktype,
        ai.ai_protocol,
        false
      )
      if listeningSocket == osInvalidSocket:
        raiseOSError(osLastError())

      try:
        listeningSocket.setBlocking(false)
        listeningSocket.setSockOptInt(SOL_SOCKET, SO_REUSEADDR, 1)
        if ipv6Only and ai.ai_family == nativesockets.toInt(Domain.AF_INET6):
          listeningSocket.setSockOptInt(
            nativesockets.toInt(Protocol.IPPROTO_IPV6).int,
            when defined(windows): ipv6OnlyOption else: IPV6_V6ONLY.int,
            1
          )

        if bindAddr(listeningSocket, ai.ai_addr, ai.ai_addrlen.SockLen) < 0:
          raiseOSError(osLastError())
        if nativesockets.listen(listeningSocket, listenBacklogLen) < 0:
          raiseOSError(osLastError())
        return listeningSocket
      except OSError as e:
        lastError = e.errorCode.OSErrorCode
        listeningSocket.close()

      ai = ai.ai_next

    if lastError != default(OSErrorCode):
      raiseOSError(lastError)
    raise newException(IOError, "Could not resolve address: " & address)
  finally:
    freeAddrInfo(aiList)

proc serveBindings(
  server: Server,
  bindings: openArray[(string, Port)],
  domain: Domain,
  ipv6Only: bool
) {.raises: [MummyError].} =
  if server.listeningSockets.len > 0:
    raise newException(MummyError, "Server already has a socket")
  if bindings.len == 0:
    raise newException(MummyError, "At least one address and port is required")

  try:
    for (address, port) in bindings:
      let listeningSocket = createListeningSocket(
        address,
        port,
        domain,
        ipv6Only
      )
      server.listeningSockets.add(listeningSocket)
      let dataEntry = DataEntry(kind: ServerSocketEntry)
      server.selector.registerHandle2(listeningSocket, {Read}, dataEntry)
  except Exception as e:
    server.destroy(true)
    raise currentExceptionAsMummyError()

  server.serving.store(true, moRelaxed)

  try:
    server.loopForever()
  except Exception as e:
    logSafely:
      error "Server loop exception",
        exception = e.msg,
        stackTrace = e.getStackTrace()
    server.destroy(false)
    raise currentExceptionAsMummyError()

proc serve*(
  server: Server,
  port: Port,
  address = "localhost"
) {.raises: [MummyError].} =
  ## The server will serve on the address and port. The default address is
  ## localhost. Use "0.0.0.0" to make the server externally accessible (with
  ## caution).
  ## This call does not return unless server.close() is called from another
  ## thread.
  server.serveBindings([(address, port)], Domain.AF_INET, false)

proc serve*(
  server: Server,
  bindings: openArray[(string, Port)]
) {.raises: [MummyError].} =
  ## The server will serve on every `(address, port)` binding. IPv4 and IPv6
  ## addresses and different ports can be used together.
  ## This call does not return unless server.close() is called from another
  ## thread.
  server.serveBindings(bindings, Domain.AF_UNSPEC, true)

proc newServer*(
  handler: RequestHandler,
  websocketHandler: WebSocketHandler = nil,
  workerThreads = max(countProcessors() * 10, 1),
  maxHeadersLen = 8 * 1024, # 8 KB
  maxBodyLen = 1024 * 1024, # 1 MB
  maxMessageLen = 64 * 1024, # 64 KB
  tcpNoDelay = true,
  requestBodyHandler: RequestBodyHandler = nil,
  requestBodyChunkSize: Positive = 64 * 1024 # 64 KB
): Server {.raises: [MummyError].} =
  ## Creates a new HTTP server. The request handler will be called for incoming
  ## HTTP requests. The WebSocket handler will be called for WebSocket events.
  ## Calls to the HTTP and WebSocket handlers are made from worker threads.
  ## When `requestBodyHandler` is set, it may select event-driven delivery for
  ## individual non-empty request bodies. Otherwise request bodies continue to
  ## be buffered and passed to the ordinary request handler. Request body calls
  ## are serialized per stream and their chunks are at most
  ## `requestBodyChunkSize` bytes.
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
  result.requestBodyHandler = requestBodyHandler
  result.maxHeadersLen = maxHeadersLen
  result.maxBodyLen = maxBodyLen
  result.maxMessageLen = maxMessageLen
  result.requestBodyChunkSize = requestBodyChunkSize
  result.tcpNoDelay = tcpNoDelay
  result.rand = initRand()

  result.workerThreads.setLen(workerThreads)

  initLock(result.taskQueueLock)
  initCond(result.taskQueueCond)
  initLock(result.responseQueueLock)
  initLock(result.sendQueueLock)
  initLock(result.requestBodyControlQueueLock)
  initLock(result.requestBodies.lock)
  initCond(result.requestBodies.cond)
  initLock(result.websocketQueuesLock)

  # Stuff that can fail
  try:
    when not defined(mummyNoWorkers):
      # Parser fuzzing does not run the selector loop; avoid allocating
      # thousands of unused Windows loopback socket pairs for SelectEvents.
      result.responseQueued = newSelectEvent()
      result.responseQueuedInitialized = true
      result.sendQueued = newSelectEvent()
      result.sendQueuedInitialized = true
      result.requestBodyControlQueued = newSelectEvent()
      result.requestBodyControlQueuedInitialized = true
      result.shutdown = newSelectEvent()
      result.shutdownInitialized = true

      result.selector = newSelector[DataEntry]()

      let responseQueuedData = DataEntry(kind: EventEntry)
      responseQueuedData.event = result.responseQueued
      result.selector.registerEvent(result.responseQueued, responseQueuedData)

      let sendQueuedData = DataEntry(kind: EventEntry)
      sendQueuedData.event = result.sendQueued
      result.selector.registerEvent(result.sendQueued, sendQueuedData)

      let requestBodyControlQueuedData = DataEntry(kind: EventEntry)
      requestBodyControlQueuedData.event = result.requestBodyControlQueued
      result.selector.registerEvent(
        result.requestBodyControlQueued,
        requestBodyControlQueuedData
      )

      let shutdownData = DataEntry(kind: EventEntry)
      shutdownData.event = result.shutdown
      result.selector.registerEvent(result.shutdown, shutdownData)

    for i in 0 ..< workerThreads:
      createThread(result.workerThreads[i], workerProc, result)
  except Exception as e:
    result.destroy(true)
    raise currentExceptionAsMummyError()

proc responded*(request: Request): bool =
  ## Check if this request has been responded.
  ## Informational responses (1xx status codes) do not mark a request responded.
  # This is only safe to call on the request handler thread right now, improve?
  request.responded

proc waitUntilReady*(server: Server, timeout: float = 10) =
  ## This proc blocks until the server is ready to receive requests or
  ## the timeout has passed. The timeout is in floating point seconds.
  ## This is useful when writing tests, where you need to know
  ## the server is ready before you begin sending requests.
  ## If the server is already ready this returns immediately.
  let start = getMonoTime()
  while true:
    if server.serving.load(moRelaxed):
      return
    let elapsed = getMonoTime() - start
    if elapsed.inMilliseconds.float > timeout * 1000:
      raise newException(MummyError, "Timeout while waiting for server")
    sleep(100)
