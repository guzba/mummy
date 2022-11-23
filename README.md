# Mummy

`nimble install mummy`

![Github Actions](https://github.com/guzba/mummy/workflows/Github%20Actions/badge.svg)

[API reference](https://nimdocs.com/guzba/mummy)

Mummy is a multi-threaded HTTP and WebSocket server written entirely in Nim.

## Why is Mummy different?

Mummy operates with this basic model: handle all socket IO multiplexed on one thread and dispatch incoming requests and WebSocket messages to a pool of worker threads.

This model has many great benefits.

## Why use Mummy?

When compared to async in Nim, Mummy means:

* Maintain the same excellent throughput of multiplexed nonblocking socket IO.

* Never needing to use `{.async.}`, `await` and deal with [functions having colors](https://journal.stuffwithstuff.com/2015/02/01/what-color-is-your-function/) ever again.

* No concern that one blocking or expensive call will stall your entire server.

* Simpler to write request handlers. Blocking the thread is totally fine! Need to make a Postgres query? No problem, just wait for the results.

When compared to traditional multi-threaded servers like Apache, Mummy:

* Keeps your server's threads away from the socket. This has many benefits, one of which is preventing a malicious actor from easily blocking all of your server's threads with a low and slow attack.

* Maintains the same simple to write request handlers.

## Example HTTP server

## Example WebSocket server

## Performance

## Testing

`nimble test`
