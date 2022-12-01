import mummy

# This example logs the HTTP method and URI of incoming requests.
# The log handler being used is the simple echo logger.

# The echo logger is a great way to get up and running fast during development.
# Once you're further along, consider upgrading to the file logger shown
# in another example.

proc handler(request: Request) =
  request.server.log(InfoLevel, request.httpMethod, " ", request.uri)
  request.respond(200)

let server = newServer(handler, logHandler = echoLogger)
echo "Serving on http://localhost:8080"
server.serve(Port(8080))
