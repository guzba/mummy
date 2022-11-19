import std/nativesockets, std/os, std/selectors, std/strutils, std/parseutils

const
  listenBacklogLen = 128
  initialSocketBufferLen = 8 * 1024
  maxSocketBufferLen = 1024 * 128 * 1024
  maxEventsPerSelectLoop = 16
  maxHeadersLen = 8192
  http10 = "HTTP/1.0"
  http11 = "HTTP/1.1"

type
  HttpVersion = enum
    Http10, Http11

  SocketData = ref object
    recvBuffer, sendBuffer: string
    bytesReceived, bytesSent: int
    request: HttpRequest
    bodyStart, nextChunkStart, contentLength: int

  HttpRequest = ref object
    clientSocket: SocketHandle
    httpMethod, httpVersion: string
    uri: string
    headers: seq[(string, string)]
    body: string

var requestQueue: seq[HttpRequest]

let serverSocket = createNativeSocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, false)
serverSocket.setBlocking(false)
serverSocket.setSockOptInt(SOL_SOCKET, SO_REUSEADDR, 1)

let addrInfo = getAddrInfo(
  "0.0.0.0",
  Port(8080),
  AF_INET,
  SOCK_STREAM,
  IPPROTO_TCP
)
try:
  if bindAddr(serverSocket, addrInfo.ai_addr, addrInfo.ai_addrlen.SockLen) < 0:
    raiseOSError(osLastError())
finally:
  freeAddrInfo(addrInfo)

if serverSocket.listen(listenBacklogLen) < 0:
  raiseOSError(osLastError())

let selector = newSelector[SocketData]()
selector.registerHandle(serverSocket, {Read}, nil)

var
  readyKeys: array[maxEventsPerSelectLoop, ReadyKey]
  receivedFrom, sentTo, needClosing: seq[SocketHandle]
while true:
  echo "===================="
  receivedFrom.setLen(0)
  sentTo.setLen(0)
  needClosing.setLen(0)
  let readyCount = selector.selectInto(-1, readyKeys)
  for i in 0 ..< readyCount:
    let readyKey = readyKeys[i]
    if readyKey.fd == serverSocket.int:
      let (clientSocket, _) = serverSocket.accept()
      if clientSocket == osInvalidSocket:
        continue
      clientSocket.setBlocking(false)
      let socketData = SocketData()
      socketData.recvBuffer.setLen(initialSocketBufferLen)
      selector.registerHandle(clientSocket, {Read}, socketData)
    else:
      echo readyKey.fd, " ", readyKey.events

      if Error in readyKey.events:
        echo readyKey.errorCode, " ", osErrorMsg(readyKey.errorCode)
        needClosing.add(readyKey.fd.SocketHandle)
        continue

      if Read in readyKey.events:
        let socketData = selector.getData(readyKey.fd)

        if socketData.recvBuffer.len == socketData.bytesReceived:
          if socketData.bytesReceived >= maxSocketBufferLen:
            needClosing.add(readyKey.fd.SocketHandle)
            continue
          socketData.recvBuffer.setLen(
            min(socketData.recvBuffer.len * 2, maxSocketBufferLen)
          )

        let bytesReceived = readyKey.fd.SocketHandle.recv(
            socketData.recvBuffer[socketData.bytesReceived].addr,
            socketData.recvBuffer.len - socketData.bytesReceived,
            0
          )
        if bytesReceived > 0:
          socketData.bytesReceived += bytesReceived

          echo "RECV FROM ", readyKey.fd, ": ", socketData.bytesReceived

          receivedFrom.add(readyKey.fd.SocketHandle)

        else:
          needClosing.add(readyKey.fd.SocketHandle)

      if Write in readyKey.events:
        let
          socketData = selector.getData(readyKey.fd)
          bytesSent = readyKey.fd.SocketHandle.send(
            socketData.sendBuffer[socketData.bytesSent].addr,
            socketData.sendBuffer.len - socketData.bytesSent,
            0
          )
        if bytesSent > 0:
          socketData.bytesSent += bytesSent

          echo "SENT TO ", readyKey.fd, ": ", socketData.bytesSent

          sentTo.add(readyKey.fd.SocketHandle)

        else:
          needClosing.add(readyKey.fd.SocketHandle)

  # Remove sockets that need closing from the dirty sockets lists
  for socketHandle in needClosing:
    var idx = sentTo.find(socketHandle)
    if idx >= 0:
      sentTo.del(idx)
    idx = receivedFrom.find(socketHandle)
    if idx >= 0:
      receivedFrom.del(idx)

  for socketHandle in sentTo:
    let socketData = selector.getData(socketHandle)
    if socketData.bytesSent == socketData.sendBuffer.len:
      needClosing.add(socketHandle) # What if in receivedFrom?
      # socketData.sendBuffer = ""
      # socketData.bytesSent = 0
      # selector.updateHandle(socketHandle, {Read})

  for socketHandle in receivedFrom:
    let socketData = selector.getData(socketHandle)

    if socketData.request == nil:
      socketData.request = HttpRequest()
      socketData.request.clientSocket = socketHandle


    # quickly determine if we have an entire request body or not

    if socketData.bodyStart == 0:
      let headersEnd = socketData.recvBuffer.find(
        "\r\n\r\n",
        0,
        min(socketData.bytesReceived, maxHeadersLen) - 1
      )
      if headersEnd < 0: # Header end not found
        if socketData.bytesReceived > maxHeadersLen:
          needClosing.add(socketHandle)
        continue

      # We have the headers
      var
        lines: seq[string]
        lineStart: int
      while true:
        let lineEnd = socketData.recvBuffer.find("\r\n", lineStart, headersEnd)
        if lineEnd == -1:
          lines.add(socketData.recvBuffer[lineStart ..< min(socketData.bytesReceived, headersEnd)])
          break
        else:
          lines.add(socketData.recvBuffer[lineStart ..< lineEnd])
          lineStart = lineEnd + 2

      let
        requestLine = lines[0]
        requestLineParts = requestLine.split(" ")
      if requestLineParts.len != 3:
        needClosing.add(socketHandle)
        continue

      echo requestLineParts

      if requestLineParts[2] != http10 and requestLineParts[2] != http11:
        needClosing.add(socketHandle)
        continue

      socketData.request.httpMethod = requestLineParts[0]
      socketData.request.uri = requestLineParts[1]
      socketData.request.httpVersion = requestLineParts[2]

      for i in 1 ..< lines.len:
        let parts = lines[i].split(": ")
        if parts.len == 2:
          socketData.request.headers.add((parts[0].toLowerAscii(), parts[1]))
        else:
          socketData.request.headers.add((lines[i], ""))

      echo socketData.request.headers

      for (k, v) in socketData.request.headers:
        if k == "transfer-encoding":
          var parts = v.split(",")
          for i in 0 ..< parts.len:
            parts[i] = parts[i].strip().toLowerAscii()
          if "chunked" in parts:
            socketData.nextChunkStart = headersEnd + 4

      if socketData.nextChunkStart == 0: # Not chunked
        var foundContentLength, needsClosing: bool
        for (k, v) in socketData.request.headers:
          if k == "content-length":
            if foundContentLength:
              needsClosing = true
              break
            foundContentLength = true
            try:
              socketData.contentLength = parseInt(v.strip())
            except:
              needsClosing = true
              break

        if needsClosing:
          needClosing.add(socketHandle)
          continue

      # This must be the last line marking that headers have been parsed
      socketData.bodyStart = headersEnd + 4

    if socketData.nextChunkStart > 0: # Chunked
      var receivedFinalChunk, needsClosing: bool
      while true:
        if socketData.nextChunkStart >= socketData.bytesReceived:
          break

        let chunkLenEnd = socketData.recvBuffer.find(
          "\r\n",
          socketData.nextChunkStart,
          min(socketData.nextChunkStart + 19, socketData.bytesReceived - 1)
        )
        if chunkLenEnd == -1:
          if socketData.bytesReceived - socketData.nextChunkStart > 19:
            needsClosing = true
          break

        var chunkLen: int
        try:
          discard parseHex(
            socketData.recvBuffer,
            chunkLen,
            socketData.nextChunkStart,
            chunkLenEnd - socketData.nextChunkStart
          )
        except:
          needsClosing = true
          break

        let chunkStart = chunkLenEnd + 2
        if chunkStart + chunkLen > socketData.bytesReceived:
          # Need to receive more bytes
          break

        if socketData.request.body.len < socketData.contentLength + chunkLen:
          socketData.request.body.setLen(max(
            socketData.request.body.len * 2,
            socketData.contentLength + chunkLen
          ))

        copyMem(
          socketData.request.body[socketData.contentLength].addr,
          socketData.recvBuffer[chunkStart].addr,
          chunkLen
        )

        socketData.contentLength += chunkLen
        socketData.nextChunkStart = chunkLenEnd + 2 + chunkLen + 2

        if chunkLen == 0:
          receivedFinalChunk = true
          break

      if needsClosing:
        needClosing.add(socketHandle)
        continue

      if not receivedFinalChunk:
        # Need to receive more bytes
        continue

      let bytesRemaining = socketData.bytesReceived - socketData.nextChunkStart
      copyMem(
        socketData.recvBuffer[0].addr,
        socketData.recvBuffer[socketData.nextChunkStart].addr,
        bytesRemaining
      )
      socketData.recvBuffer.setLen(max(bytesRemaining, initialSocketBufferLen))
      socketData.bytesReceived = bytesRemaining
      socketData.nextChunkStart = 0

      socketData.request.body.setLen(socketData.contentLength)

      echo "GOT ENTIRE CHUNKED REQUEST"

      requestQueue.add(move socketData.request)

    else:
      let requestLen = socketData.bodyStart + socketData.contentLength
      if requestLen < socketData.bytesReceived:
        # Need to receive more bytes
        discard
      else:
        # We have the entire request
        if socketData.contentLength > 0:
          socketData.request.body.setLen(socketData.contentLength)
          copyMem(
            socketData.request.body[0].addr,
            socketData.recvBuffer[socketData.bodyStart].addr,
            socketData.contentLength
          )
          socketData.contentLength = 0
        let bytesRemaining = socketData.bytesReceived - requestLen
        copyMem(
          socketData.recvBuffer[0].addr,
          socketData.recvBuffer[requestLen].addr,
          bytesRemaining
        )
        socketData.recvBuffer.setLen(max(bytesRemaining, initialSocketBufferLen))
        socketData.bytesReceived = bytesRemaining

        echo "GOT ENTIRE REQUEST"

        requestQueue.add(move socketData.request)

  for socketHandle in needClosing:
    selector.unregister(socketHandle)
    socketHandle.close()

  for request in requestQueue:
    echo "QUEUE HANDLE REQ"
    let socketData = selector.getData(request.clientSocket)
    socketData.sendBuffer = "HTTP/1.1 200\r\nContent-Length: 0\r\n\r\n"
    selector.updateHandle(request.clientSocket, {Read, Write})

  requestQueue.setLen(0)
