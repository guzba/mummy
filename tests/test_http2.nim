import httpclient, jsony, mummy, std/random

randomize()

type TestObject = object
  val: int

proc handler(request: Request) =
  case request.uri:
  of "/":
    if request.httpMethod == "POST":
      var headers: mummy.HttpHeaders
      headers["Content-Type"] = "application/json"
      let
        jsonIn = fromJson(request.body, TestObject)
        jsonOut = toJson(TestObject(val: jsonIn.val + 1))
      request.respond(200, headers, jsonOut)
    else:
      request.respond(405)
  else:
    request.respond(404)

let server = newServer(handler)

const requesterThreadNum =
  when defined(linux):
    100
  else:
    3

var
  requesterThreads = newSeq[Thread[void]](requesterThreadNum)
  waitingThread: Thread[void]

proc requesterProc() =
  server.waitUntilReady()

  for i in 0 ..< 10:
    let client = newHttpClient()
    var to: TestObject
    to.val = rand(0 ..< 100)
    let response = client.post("http://localhost:8081/", toJson(to))
    doAssert fromJson(response.body, TestObject).val == to.val + 1

for requesterThread in requesterThreads.mitems:
  createThread(requesterThread, requesterProc)

proc waitProc() =
  {.gcsafe.}:
    joinThreads(requesterThreads)
    echo "Done, shut down the server"
    server.close()

createThread(waitingThread, waitProc)

# Start the server
server.serve(Port(8081))
