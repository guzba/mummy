import mummy, std/nativesockets, std/os

when defined(windows):
  import winlean
elif defined(posix):
  import posix

const port = Port(8081)

proc handler(request: Request) =
  request.respond(404)

let server = newServer(handler)

var requesterThread: Thread[void]

proc requesterProc() =
  server.waitUntilReady()

  proc openTcpSocket(): SocketHandle =
    result = createNativeSocket(
      Domain.AF_INET,
      SockType.SOCK_STREAM,
      Protocol.IPPROTO_TCP,
      false
    )
    if result == osInvalidSocket:
      raiseOSError(osLastError())

    let ai = getAddrInfo(
      "localhost",
      port,
      Domain.AF_INET,
      SockType.SOCK_STREAM,
      Protocol.IPPROTO_TCP,
    )
    try:
      if result.connect(ai.ai_addr, ai.ai_addrlen.SockLen) < 0:
        raiseOSError(osLastError())
    finally:
      freeAddrInfo(ai)

  block:
    let socket = openTcpSocket()

    let clte = "POST /search HTTP/1.1\r\nHost: vulnerable-website.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 49\r\nTransfer-Encoding: chunked\r\n\r\ne\r\nq=smuggling&x=\r\n0\r\n\r\nGET /404 HTTP/1.1\r\nFoo: x"

    if socket.send(clte.cstring, clte.len.cint, 0) < 0:
      raiseOSError(osLastError())

    var recvBuf = newString(4096)
    let bytesReceived = socket.recv(
      recvBuf[0].addr,
      recvBuf.len.cint,
      0
    )

    doAssert bytesReceived == 0

    socket.close()

  block:
    let socket = openTcpSocket()

    let tecl = "POST /search HTTP/1.1\r\nHost: vulnerable-website.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n7c\r\nGET /404 HTTP/1.1\r\nHost: vulnerable-website.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 144\r\n\r\nx=\r\n0\r\n"
    if socket.send(tecl.cstring, tecl.len.cint, 0) < 0:
      raiseOSError(osLastError())

    var recvBuf = newString(4096)
    let bytesReceived = socket.recv(
      recvBuf[0].addr,
      recvBuf.len.cint,
      0
    )

    doAssert bytesReceived == 0

    socket.close()

  echo "Done, shut down the server"
  server.close()

createThread(requesterThread, requesterProc)

server.serve(port)
