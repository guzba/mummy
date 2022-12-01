# Mummy

`nimble install mummy`

![Github Actions](https://github.com/guzba/mummy/workflows/Github%20Actions/badge.svg)

[API reference](https://nimdocs.com/guzba/mummy)

Mummy is a multi-threaded HTTP and WebSocket server written entirely in Nim.

*A return to the ancient ways of threads.*

Mummy has been written specifically to maximize the performance of your server hardware without compromising on programmer happiness.

* Supports HTTP keep-alive and gzip response compression automatically.
* Built-in first-class WebSocket support.
* Multiplexed socket IO without the `{.async.}` price.

⚠️ Mummy is brand new so please exercise reasonable caution!

## How is Mummy different?

Mummy operates with this basic model: handle all socket IO on one thread and dispatch incoming HTTP requests and WebSocket events to a pool of worker threads. Your HTTP handlers probably won't even need to think about threads at all.

This model has many great benefits and is ready to take advantage of continued server core count increases (AMD just announced a 96 core 192 thread sever CPU!).

## Why use Mummy instead of async?

* No more needing to use `{.async.}`, `Future[]`, `await` etc and deal with [functions having colors](https://journal.stuffwithstuff.com/2015/02/01/what-color-is-your-function/).

* Maintain the same excellent throughput of multiplexed nonblocking socket IO.

* No concern that one blocking or expensive call will stall your entire server.

* Async blocks on surprising things like DNS resolution and file reads which will stall all request handling.

* Simpler to write request handlers. Blocking the thread is totally fine! Need to make a Postgres query? No problem, just wait for the results.

* There is substantial advantage to writing simpler code vs theoretically fast but possibly convoluted and buggy code.

* Much simpler debugging. Async stack traces are huge and confusing.

* Easier error handling, just `try except` like you normally do. Uncaught exceptions in Mummy handlers also do not bring down your entire server.

* Mummy handles the threading and dispatch so your handlers may not need to think about threads at all.

* Takes advantage of multiple cores and the amazing work of the Nim team on ARC / ORC and Nim 2.0.

## Why prioritize WebSockets?

WebSockets are wonderful and can have substantial advantages over more traditional API paradigms like REST and various flavors of RPC.

Unfortunately, most HTTP servers pretend WebSockets don't exist.

This means developers need to hack support in through additional dependencies, hijacking connections etc and it all rarely adds up into something really great.

I see no reason why Websockets should not work exceptionally well right out of the box, saving developers a lot of uncertainty and time researching which of the possible ways to wedge WebSocket support in to an HTTP server is "best".

## What is Mummy not great for?

Everything comes with trade-offs. Mummy is focused on being an exceptional API server. Think REST, JSON, RPC, WebSockets, HTML from templates etc.

The property these share in common is they are all relatively memory-light. Most things are, which is great, but if you're specifically going to be serving a lot of very large files or expect large file uploads, Mummy is probably not the best choice.

Why is Mummy not great for large files? This is because Mummy dispatches fully received in-memory requests to worker threads and sends in-memory responses. This is great for everything except very large files.

## Example HTTP server

```nim
proc handler(request: Request) =
  case request.uri:
  of "/":
    if request.httpMethod == "GET":
      var headers: HttpHeaders
      headers["Content-Type"] = "text/plain"
      request.respond(200, headers, "Hello, World!")
    else:
      request.respond(405)
  else:
    request.respond(404)

let server = newServer(handler)
server.serve(Port(8080))
```

## Example WebSocket server

```nim
proc handler(request: Request) =
  case request.uri:
  of "/":
    if request.httpMethod == "GET":
      let websocket = request.upgradeToWebSocket()
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
server.serve(Port(8080))
```

## Performance

Benchmarking HTTP servers is a bit like benchmarking running shoes.

Certainly, there are some terrible shoes to run in (heels, clogs, etc), but once you're in a reasonable pair of shoes it is the runner that's going to matter, not the shoes.

In this analogy, the runner is what your handers are actually doing and the shoes are the HTTP server choice.

With that in mind, I suggest three priorities:

1) Ensure your HTTP server choice does not unnecessarily hamper performance.

2) Avoid HTTP servers that have easy performance vulnerabilities.

3) Prioritize what will enable you to write and maintain performant and reliable handlers.

I believe Mummy clears all three priorities:

1) Mummy prioritizes efficiency in receiving and dispatching incoming requests and sending outgoing responses. This means things like avoiding unnecessary memory copying, ensuring the CPU spends all of its time in your handlers.

2) Because Mummy uses multiplexed IO just like async, Mummy is not vulnerable to attacks like low-and-slow which traditionally multi-threaded servers are vulnerable to. Additionally, while a single blocking or CPU heavy operation can stall an entire async server, this is not a problem for Mummy.

3) Request handlers with Mummy are just plain-old inline Nim code. They have a straightforward request-in-response-out API. Keeping things simple is great for maintenance, reliability and performance.

## Benchmarks

Benchmarking was done on an Ubuntu 22.04 server with a 4 core / 8 thread CPU.

The tests/wrk_ servers that are being benchmarked attempt to simulate requests that take ~10ms to complete.

All benchmarks were tested by:

`wrk -t10 -c100 -d10s http://localhost:8080`

The exact commands for each server are:

`nim c --mm:orc --threads:on -d:release -r tests/wrk_mummy.nim`
Requests/sec:   9547.56

`nim c --mm:orc --threads:off -d:release -r tests/wrk_asynchttpserver.nim`
Requests/sec:   7979.67)

`nim c --mm:orc --threads:on -d:release -r tests/wrk_httpbeast.nim`
Requests/sec:     99.85

`nim c --mm:orc --threads:off -d:release -r tests/wrk_jester.nim`
(--threads:on segfaults)
Requests/sec:     99.82

`nim c --mm:orc --threads:on -d:release -r tests/wrk_prologue.nim`
Requests/sec:     99.83

HttpBeast, Jester and Prologue all seem to suffer from the same substantial performance drop when using `await` in a handler (which is exactly what you'll be doing in an async server).

## Testing

A fuzzer has been run against Mummy's socket reading and parsing code to ensure Mummy does not crash or otherwise misbehave on bad data from sockets. You can run the fuzzer any time by running `nim c -r tests/fuzz_recv.nim`.
