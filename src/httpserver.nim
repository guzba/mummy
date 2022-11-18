import std/nativesockets, std/os, std/selectors

const
  listenBacklogLen = 128
  initialSocketBufferLen = 8192
  maxEventsPerSelectLoop = 16

type SocketData = ref object
  recvBuffer, sendBuffer: string
  bytesReceived, bytesSent: int

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

var readyKeys: array[maxEventsPerSelectLoop, ReadyKey]
while true:
  echo "===================="
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

      echo "ACCEPTED ", clientSocket.int

    else:
      if Read in readyKey.events:
        let
          socketData = selector.getData(readyKey.fd)
          bytesReceived = readyKey.fd.SocketHandle.recv(
            socketData.recvBuffer[socketData.bytesReceived].addr,
            socketData.recvBuffer.len - socketData.bytesReceived,
            0
          )
        if bytesReceived > 0:
          socketData.bytesReceived += bytesReceived

          # Pretend it always finishes
          socketData.recvBuffer.setLen(initialSocketBufferLen)
          socketData.bytesReceived = 0
          socketData.sendBuffer = "HTTP/1.1 200\r\nKeep-Alive: timeout=60, max=1000\r\nContent-Length: 2\r\n\r\nOK"
          selector.updateHandle(readyKey.fd, {Read, Write})

          echo "RECV FROM ", readyKey.fd

        else:
          selector.unregister(readyKey.fd)

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

          # Pretend it always finishes
          socketData.sendBuffer = ""
          socketData.bytesSent = 0
          selector.updateHandle(readyKey.fd, {Read})

          echo "SENT TO ", readyKey.fd

        else:
          selector.unregister(readyKey.fd)
