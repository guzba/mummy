import httpserver, std/asyncdispatch, std/os, ws

var serverThread: Thread[void]

proc serverProc() =
  ## Runs the server in a thread

  proc handler(request: HttpRequest, response: var HttpResponse) =
    let ws = request.websocketUpgrade(response)
    ws.send("ASDF")
    ws.send("Second", BinaryMsg)

  proc onOpen(websocket: httpserver.WebSocket) =
    echo "onOpen"

  proc onMessage(websocket: httpserver.WebSocket, kind: WsMsgKind, data: string) =
    echo "onMessage"

  proc onClose(websocket: httpserver.WebSocket) =
    echo "onClose"

  let server = newHttpServer(handler, onOpen, onMessage, onClose)
  server.serve(Port(8081))

createThread(serverThread, serverProc)

sleep(1000)

let websocket = waitFor newWebSocket("ws://127.0.0.1:8081")
echo "C2S"
waitFor websocket.ping()
waitFor websocket.send("Client to server")
echo waitFor websocket.receivePacket()
echo "!!"
echo waitFor websocket.receivePacket()
websocket.close()
waitFor sleepAsync(1000)
