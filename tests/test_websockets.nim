import mummy, std/os, std/asyncdispatch, ws

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
  event: WebSocketEventKind,
  message: string,
  messageKind: MessageKind
) =
  case event:
  of OpenEvent:
    websocket.send("Second")
  of MessageEvent:
    doAssert message == "Third"
    websocket.send("Fourth", BinaryMessage)
  of ErrorEvent:
    echo "Error occurred"
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
  # websocket.hangUp()
  waitFor sleepAsync(100)

  echo "Done, shut down the server"
  server.close()

createThread(requesterThread, requesterProc)

# Start the server
server.serve(Port(8081))
