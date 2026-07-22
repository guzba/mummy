import mummy, std/[assertions, nativesockets, os, strutils]

const testPort = Port(18081)

proc handler(request: Request) =
  request.respond(200, body = "Hello from Mummy!")

proc fetch(address: string, domain: Domain): string =
  let socket = createNativeSocket(
    domain,
    SockType.SOCK_STREAM,
    Protocol.IPPROTO_TCP,
    false
  )
  if socket == osInvalidSocket:
    raiseOSError(osLastError())

  try:
    let ai = getAddrInfo(
      address,
      testPort,
      domain,
      SockType.SOCK_STREAM,
      Protocol.IPPROTO_TCP,
    )
    try:
      if socket.connect(ai.ai_addr, ai.ai_addrlen.SockLen) < 0:
        raiseOSError(osLastError())
    finally:
      freeAddrInfo(ai)

    let request = "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"
    if socket.send(request.cstring, request.len.cint, 0) < 0:
      raiseOSError(osLastError())

    var buffer = newString(4096)
    while true:
      let bytesReceived = socket.recv(buffer[0].addr, buffer.len.cint, 0)
      if bytesReceived < 0:
        raiseOSError(osLastError())
      if bytesReceived == 0:
        break
      result.add(buffer[0 ..< bytesReceived])
  finally:
    socket.close()

let server = newServer(handler)
var requesterThread: Thread[void]

proc requesterProc() =
  server.waitUntilReady()
  try:
    let ipv4Response = fetch("127.0.0.1", Domain.AF_INET)
    doAssert ipv4Response.endsWith("Hello from Mummy!")

    let ipv6Response = fetch("::1", Domain.AF_INET6)
    doAssert ipv6Response.endsWith("Hello from Mummy!")
  finally:
    server.close()

createThread(requesterThread, requesterProc)

server.serve(testPort, ["0.0.0.0", "::"])
