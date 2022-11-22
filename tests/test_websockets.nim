import mummy, std/asyncdispatch, std/os, ws

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

proc websocketHandler(
  websocket: mummy.WebSocket,
  event: WebSocketEvent,
  message: Message
) =
  case event:
  of OpenEvent:
    websocket.send("Second")
  of MessageEvent:
    case message.kind:
    of TextMessage:
      doAssert message.data == "Third"
    of BinaryMessage:
      doAssert false
    of mummy.Ping:
      doAssert false
    of mummy.Pong:
      doAssert false
    websocket.send("Fourth", BinaryMessage)
  of ErrorEvent:
    discard
  of CloseEvent:
    echo "Closed websocket connection"

let server = newServer(handler, websocketHandler)

var requesterThread: Thread[void]

proc requesterProc() =
  sleep(1000) # Give the server some time to start up

  let websocket = waitFor newWebSocket("ws://127.0.0.1:8081")
  doAssert (waitFor websocket.receiveStrPacket()) == "First"
  doAssert (waitFor websocket.receiveStrPacket()) == "Second"
  waitFor websocket.send("Third")
  doAssert (waitFor websocket.receiveBinaryPacket()) == cast[seq[byte]]("Fourth")
  websocket.close()
  websocket.hangUp()
  waitFor sleepAsync(100)

  echo "Done, shut down the server"
  server.close()

createThread(requesterThread, requesterProc)

# Start the server
server.serve(Port(8081))
