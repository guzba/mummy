# Mummy

`nimble install mummy`

![Github Actions](https://github.com/guzba/mummy/workflows/Github%20Actions/badge.svg)

[API reference](https://nimdocs.com/guzba/mummy)

Mummy is a multi-threaded HTTP and WebSocket server written entirely in Nim.

Mummy has been written specifically to maximize the performance of your server hardware without compromising on programmer happiness.

* Supports HTTP keep-alive and gzip response compression automatically.
* Built-in first-class WebSocket support.
* Multiplexed socket IO without the `{.async.}` price.

## How is Mummy different?

Mummy operates with this basic model: handle all socket IO multiplexed on one thread and dispatch incoming requests and WebSocket events to a pool of worker threads.

This model has many great benefits and is ready to take advantage of continued server core count increases (AMD just announced a 96 core 192 thread sever CPU!).

## Why use Mummy?

When compared to async in Nim, Mummy means:

* Never needing to use `{.async.}`, `await` and deal with [functions having colors](https://journal.stuffwithstuff.com/2015/02/01/what-color-is-your-function/) ever again.

* Maintain the same excellent throughput of multiplexed nonblocking socket IO.

* No concern that one blocking or expensive call will stall your entire server.

* Simpler to write request handlers. Blocking the thread is totally fine! Need to make a Postgres query? No problem, just wait for the results.

* Takes advantage of multiple cores.

When compared to traditional multi-threaded servers like Apache, Mummy:

* Keeps your server's threads away from the socket. This has many benefits, one of which is preventing a malicious actor from easily blocking all of your server's threads with a low and slow attack.

* Maintains the same simple to write request handlers.

## What is Mummy not great for?

Everything comes with trade-offs. Mummy is focused on being an exceptional API server. Think REST, JSON RPC, WebSockets, HTML from templates etc.

The property these share in common is they are all relatively memory-light. Most things are, which is great, but if you're specifically going to be serving a lot of very large files or expect large file uploads, Mummy is probably not the best choice.

Why is Mummy not great for large files? This is because Mummy dispatches fully received in-memory requests to worker threads and sends in-memory responses. This is great for everything except very large files.

## Example HTTP server

## Example WebSocket server

## Performance

## Testing
