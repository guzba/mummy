import mummy, std/asyncdispatch, ws

proc handler(request: Request) =
  case request.uri:
  of "/":
    if request.httpMethod == "GET":
      let websocket = request.upgradeToWebSocket()
      websocket.send("First")
    else:
      request.respond(405)
  else:
    request.respond(404)

var n: int

proc websocketHandler(
  websocket: mummy.WebSocket,
  event: WebSocketEvent,
  message: Message
) =
  case event:
  of OpenEvent:
    doAssert n == 0
    n += 1
    websocket.send("Second")
  of MessageEvent:
    case message.kind:
    of TextMessage:
      doAssert n == 1
      n += 1
      doAssert message.data == "Third"
    of BinaryMessage:
      doAssert n == 2
      n += 1
      doAssert message.data == "Fourth"
    of mummy.Ping:
      doAssert n == 3
      n += 1
      doAssert message.data == ""
    of mummy.Pong:
      doAssert false
    websocket.send("Fifth", BinaryMessage)
  of ErrorEvent:
    discard
  of CloseEvent:
    doAssert n == 4
    echo "Closed websocket connection"

let server = newServer(handler, websocketHandler)

var requesterThread: Thread[void]

proc requesterProc() =
  server.waitUntilReady()

  let websocket = waitFor newWebSocket("ws://127.0.0.1:8081")
  doAssert (waitFor websocket.receiveStrPacket()) == "First"
  doAssert (waitFor websocket.receiveStrPacket()) == "Second"
  waitFor websocket.send("Third")
  waitFor websocket.send("Fourth", Binary)
  waitFor websocket.send("", Opcode.Ping)
  doAssert (waitFor websocket.receiveBinaryPacket()) == cast[seq[byte]]("Fifth")
  websocket.close()
  websocket.hangUp()
  waitFor sleepAsync(100)

  echo "Done, shut down the server"
  server.close()

createThread(requesterThread, requesterProc)

# Start the server
server.serve(Port(8081))
