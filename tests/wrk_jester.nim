import asyncdispatch, jester, strutils, wrk_shared

settings:
  port = Port(8080)

routes:
  get "/":
    {.gcsafe.}:
      resp responseBody
