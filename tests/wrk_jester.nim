import asyncdispatch, jester, strutils, wrk_shared

settings:
  port = Port(8080)

routes:
  get "/":
    {.gcsafe.}:
      await sleepAsync(10)
      resp responseBody
