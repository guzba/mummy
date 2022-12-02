import prologue, wrk_shared

proc hello*(ctx: Context) {.async.} =
  {.gcsafe.}:
    await sleepAsync(10)
    resp responseBody

let app = newApp()
app.get("/", hello)
app.run()
