import asyncdispatch, jester, strutils, wrk_shared

routes:
  get "/":
    {.gcsafe.}:
      resp responseBody
