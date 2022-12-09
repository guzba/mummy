import mummy, mummy/routers, std/locks, std/sets

## This example shows a basic chat server over WebSocket.
##
## To try the example, run the server (nim c -r examples/chat.nim)
## then open a few tabs to http://localhost:8080
##
## Each tab can send messages and they'll be received by all tabs.
##
## This file includes the HTML being sent to the client as a string. In a real
## web app, you'd probably have this in a file or served some other way.
## I'm just keeping everything in one file and as simple as possible.

var
  lock: Lock
  clients: HashSet[WebSocket]

initLock(lock)

proc indexHandler(request: Request) =
  var headers: HttpHeaders
  headers["Content-Type"] = "text/html"
  request.respond(200, headers, """
  <!DOCTYPE html>
  <script>
    var ws = new WebSocket("ws://localhost:8080/chat")
    ws.onmessage = function(event) {
      var div = document.createElement('div')
      div.textContent = event.data
      document.body.appendChild(div)
    }
    ws.onerror = function(event) {
      var div = document.createElement('div')
      div.textContent = "! WebSocket error"
      document.body.appendChild(div)
    }
    var send = function() {
      ws.send(document.getElementById('msg').value)
    }
  </script>
  <input id="msg" type="text">
  <input type="button" onclick="send()" value="Send">
  <div>Messages received:</div>
  """)

proc upgradeHandler(request: Request) =
  let websocket = request.upgradeToWebSocket()
  websocket.send("Hello from WebSocket server!")

proc websocketHandler(
  websocket: WebSocket,
  event: WebSocketEvent,
  message: Message
) =
  case event:
  of OpenEvent:
    echo "Client connected"
    # When a new client connects, we add it to a set of connected clients.
    # Mummy uses threads so we need to lock the global memory
    # before we modify it.
    {.gcsafe.}:
      withLock lock:
        clients.incl(websocket)
  of MessageEvent:
    echo "Message received from client"
    # To broadcast this message to all clients, we need to lock the global
    # set of connected clients so it does not get modified while we are
    # iterating.
    {.gcsafe.}:
      withLock lock:
        for client in clients:
          client.send(message.data)
  of ErrorEvent:
    discard
  of CloseEvent:
    echo "Client disconnected"
    # When a client disconnects, remove it from the set of connected clients.
    {.gcsafe.}:
      withLock lock:
        clients.excl(websocket)

var router: Router
router.get("/", indexHandler)
router.get("/chat", upgradeHandler)

let server = newServer(router, websocketHandler)
echo "Serving on http://localhost:8080"
server.serve(Port(8080))
