import mummy

proc handler(request: Request) =
  case request.uri:
  of "/":
    if request.httpMethod == "GET":
      var headers: HttpHeaders
      headers["Content-Type"] = "text/html"
      request.respond(200, headers, """
      <script>
        var ws = new WebSocket("ws://localhost:8080/ws");
        ws.onmessage = function (event) {
          document.body.innerHTML = event.data;
        };
      </script>
      """)
    else:
      request.respond(405)
  of "/ws":
    if request.httpMethod == "GET":
      let websocket = request.upgradeToWebSocket()
      websocket.send("Hello world from WebSocket!")
      websocket.close()
    else:
      request.respond(405)
  else:
    request.respond(404)

proc websocketHandler(
  websocket: WebSocket,
  event: WebSocketEvent,
  message: Message
) =
  case event:
  of OpenEvent:
    discard
  of MessageEvent:
    echo message.kind, ": ", message.data
  of ErrorEvent:
    discard
  of CloseEvent:
    discard

let server = newServer(handler, websocketHandler)
echo "Serving on http://localhost:8080"
server.serve(Port(8080))
