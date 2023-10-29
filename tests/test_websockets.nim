import mummy, std/asyncdispatch, whisky

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
  message: mummy.Message
) =
  case event:
  of OpenEvent:
    doAssert n == 0
    n += 1
    websocket.send("Second")
  of MessageEvent:
    case message.kind:
    of mummy.TextMessage:
      doAssert n == 1
      n += 1
      doAssert message.data == "Third"
    of mummy.BinaryMessage:
      doAssert n == 2
      n += 1
      doAssert message.data == "Fourth"
    of mummy.Ping:
      doAssert n == 3
      n += 1
      doAssert message.data == ""
    of mummy.Pong:
      doAssert false
    var fifth: string
    for i in 0 ..< 0xffff + 1:
      fifth.add 'a'
    websocket.send(fifth, mummy.BinaryMessage)
  of ErrorEvent:
    discard
  of CloseEvent:
    doAssert n == 4
    echo "Closed websocket connection"

let server = newServer(handler, websocketHandler)

var requesterThread: Thread[void]

proc requesterProc() =
  server.waitUntilReady()

  let ws = newWebSocket("ws://127.0.0.1:8081")
  doAssert ws.receiveMessage() ==
    some(whisky.Message(kind: whisky.TextMessage, data: "First"))
  doAssert ws.receiveMessage() ==
    some(whisky.Message(kind: whisky.TextMessage, data: "Second"))
  ws.send("Third")
  ws.send("Fourth", whisky.BinaryMessage)
  ws.send("", whisky.Ping)
  let fifth = ws.receiveMessage()
  doAssert fifth.get.kind == whisky.BinaryMessage
  doAssert fifth.get.data.len == 0xffff + 1
  ws.close()

  echo "Done, shut down the server"
  server.close()

createThread(requesterThread, requesterProc)

# Start the server
server.serve(Port(8081))
