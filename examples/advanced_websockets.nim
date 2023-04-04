import mummy, mummy/routers, std/locks, std/sets, std/tables, std/selectors, ready

## This is a more complex example of using Mummy as a WebSocket server.
##
## WebSocket clients subscribe to a channel based on the url, eg /<channel_name>.
## Those clients will then receive any messages published to <channel_name>.
##
## Redis is used as the messaging hub so that multiple instances can run and
## messages can be pubished from other servers. To enable this, Redis PubSub
## is used. (Check out the Redis docs on that to learn more.)
##
## This server sends a heartbeat message to websocket clients at least every 30
## seconds. This ensure the connection stays open and active in a way WebSocket
## clients can check (for example, WebSocket Ping/Pong is not visible to JS).

const
  workerThreads = 4 # The number of threads handling incoming HTTP requests and WebSocket messages
  port = 8123 # The HTTP port to listen on.
  heartbeatMessage = """{"type":"heartbeat"}""" # The JSON heartbeat message.

let pubsubRedis = newRedisConn() # The Redis connection used for PubSub

var
  lock: Lock # The lock for global memory, just one lock is fine
  clientToChannel: Table[WebSocket, string] # Store what channel this WebSocket is subscribed to
  channels: Table[string, HashSet[WebSocket]] # Map from a channel to its WebSockets
  heartbeatBuckets: array[30, HashSet[WebSocket]]  # The buckets of WebSockets to send a heartbeats to

# Remember to initialize the lock.
initLock(lock)

# This is the HTTP handler for /* requests. These requests are upgraded to WebSockets.
proc upgradeHandler(request: Request) =
  let channel = request.uri[1 .. ^1] # Everything after / is the channel name.

  # We need to take the lock on global memory, upgrade to WebSocket and store
  # what channel this WebSocket subscribed to since we will not have `.uri` later.
  {.gcsafe.}:
    withLock lock:
      let websocket = request.upgradeToWebSocket()
      clientToChannel[websocket] = channel

# This is the proc that the thread dedicated to receiving on the
# Redis PubSub connection runs. This thread loops forever receiving on the Redis
# connection. When a reply comes in, it is handled based on the type of event
# it is.
proc receiveThreadProc() =
  try:
    while true:
      let
        reply = pubsubRedis.receive() # Wait for the next reply from Redis.
        event = reply[0].to(string)
      case event:
      of "subscribe", "unsubscribe":
        discard
      of "message":
        # If we have received message, send it to the WebSockets subscribed
        # to that channel.
        let
          channel = reply[1].to(string)
          message = reply[2].to(string)
        # We need to get the set of clients connected to this channel.
        # To do this, we take the global memory lock and copy the current
        # set of subscribed clients.
        # We can then release the lock and send to those clients.
        var clients: HashSet[WebSocket]
        {.gcsafe.}:
          withLock lock:
            if channel in channels:
              clients = channels[channel] # Intentionally take a copy
        if clients.len > 0:
          for websocket in clients:
            websocket.send(message, TextMessage)
        else:
          echo "Dropped message to channel without clients"
      else:
        echo "Unexpected Redis PubSub event: ", event
  except:
    echo "Fatal error in receive thread: ", getCurrentExceptionMsg()
    quit(1)

# The Redis PubSub receive thread.
var receiveThread: Thread[void]
createThread(receiveThread, receiveThreadProc)

# This is the proc tha the thread dedicated to sending heartbeat messages runs.
proc heartbeatThreadProc() =
  try:
    # Set up a selector with a timer to wake up every second.
    # You could use sleep(1000) instead, however you'll slowly fall behind
    # as your interval will become 1 second + any time spent doing the work.
    # I prefer this method but it is more advanced and probably not necessary.
    let heartbeatRateSelector = newSelector[int]()
    discard registerTimer(heartbeatRateSelector, 1 * 1000, false, 0)
    var
      readyKeys: array[1, ReadyKey]
      bucket: int
    while true:
      # Block here until our timer wakes us up
      discard heartbeatRateSelector.selectInto(-1, readyKeys)
      # We have woken up, time to send some heartbeats.
      # We send a heartbeat every 30 seconds so we have 30 heartbeat buckets.
      # To evently spread the workload, each WebSocket is added to one of the
      # buckets. All we need to do is wake up, grab the next bucket and send
      # the heartbeat messages out.
      # Lock global memory and copy out the current set of clients for this bucket.
      var clients: HashSet[WebSocket]
      {.gcsafe.}:
        withLock lock:
          clients = heartbeatBuckets[bucket]
      # Release the lock and send the heartbeats to those clients.
      for websocket in clients:
        websocket.send(heartbeatMessage)
      # Move to next bucket for next tick.
      bucket = (bucket + 1) mod heartbeatBuckets.len
  except:
    echo "Fatal error in heartbeat thread: ", getCurrentExceptionMsg()
    quit(1)

# The heartbeat thread.
var heartbeatThread: Thread[void]
createThread(heartbeatThread, heartbeatThreadProc)

# WebSocket events are received by this handler.
proc websocketHandler(
  websocket: WebSocket,
  event: WebSocketEvent,
  message: Message
) =
  case event:
  of OpenEvent:
    # We have just opened a new WebSocket. Send an initial heartbeat and
    # get it wired up to receive messages.

    websocket.send(heartbeatMessage)

    var
      channel: string
      needsSubscribe: bool

    # Lock global memory and get this WebSocket wired up.
    {.gcsafe.}:
      withLock lock:
        if websocket in clientToChannel:
          channel = clientToChannel[websocket] # Grab the channel this WebSocket subscribed to.
          if channel notin channels: # If this is a new channel, set it up.
            channels[channel] = initHashSet[WebSocket]()
            needsSubscribe = true # Since this is a new channel we need to tell Redis.
          channels[channel].incl(websocket) # Add this WebSocket to the channel subscriber set.
          # Add this WebSocket to a heartbeat bucket.
          let bucket = abs(websocket.hash()) mod heartbeatBuckets.len
          heartbeatBuckets[bucket].incl(websocket)
        else:
          echo "No clientToChannel entry at websocket open"

    # If this is a new channel we need to send Redis a "SUBSCRIBE" command for it
    if needsSubscribe:
      pubsubRedis.send("SUBSCRIBE", channel)

  of MessageEvent:
    if message.kind == Ping:
      websocket.send("", Pong)

  of ErrorEvent:
    discard

  of CloseEvent:
    # A WebSocket has closed. Time to clean things up.

    var
      channel: string
      needsUnsubscribe: bool

    # Lock global memory and remove the WebSocket.
    {.gcsafe.}:
      withLock lock:
        if websocket in clientToChannel:
          channel = clientToChannel[websocket]
          if channel in channels:
            channels[channel].excl(websocket)
            let bucket = abs(websocket.hash()) mod heartbeatBuckets.len
            heartbeatBuckets[bucket].excl(websocket)
            if channels[channel].len == 0:
              channels.del(channel)
              needsUnsubscribe = true
          else:
            echo "No channels entry for channel at websocket close"
        else:
          echo "No clientToChannel entry at websocket close"

        # If there are no longer any subscribers to this channel, we tell Redis
        # we don't care about messages to that channel anymore by
        # sending the "UNSUBSCRIBE" command.
        if needsUnsubscribe:
          pubsubRedis.send("UNSUBSCRIBE", channel)

# A simple router sending all requests to be upgraded to WebSockets.
var router: Router
router.get("/*", upgradeHandler)

let server = newServer(
  router,
  websocketHandler,
  workerThreads = workerThreads
)
echo "Serving on localhost port ", port
server.serve(Port(port))
