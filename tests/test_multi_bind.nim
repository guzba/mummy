import mummy, std/[assertions, net, strutils]

const
  testPort = Port(18081)
  otherPort = Port(18082)
  requestTimeout = 5_000

proc handler(request: Request) =
  request.respond(200, body = "Hello from Mummy!")

block emptyBindings:
  let emptyServer = newServer(handler)
  doAssertRaises MummyError:
    emptyServer.serve([])
  doAssertRaises MummyError:
    emptyServer.waitUntilReady(0.1)
  emptyServer.close()

proc fetch(address: string, port: Port, domain: Domain): string =
  let socket = newSocket(
    domain,
    SockType.SOCK_STREAM,
    Protocol.IPPROTO_TCP,
    buffered = false
  )

  try:
    socket.connect(address, port, timeout = requestTimeout)

    let request = "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"
    socket.send(request)

    while true:
      let chunk = socket.recv(4096, timeout = requestTimeout)
      if chunk.len == 0:
        break
      result.add(chunk)
  finally:
    socket.close()

let server = newServer(handler)
var requesterThread: Thread[void]

proc requesterProc() =
  server.waitUntilReady()
  try:
    let ipv4Response = fetch("127.0.0.1", testPort, Domain.AF_INET)
    doAssert ipv4Response.endsWith("Hello from Mummy!")

    let ipv6Response = fetch("::1", testPort, Domain.AF_INET6)
    doAssert ipv6Response.endsWith("Hello from Mummy!")

    let otherPortResponse = fetch("127.0.0.1", otherPort, Domain.AF_INET)
    doAssert otherPortResponse.endsWith("Hello from Mummy!")
  finally:
    server.close()

createThread(requesterThread, requesterProc)

server.serve([
  ("0.0.0.0", testPort),
  ("::", testPort),
  ("127.0.0.1", otherPort)
])
