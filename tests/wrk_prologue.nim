import prologue, wrk_shared

proc hello*(ctx: Context) {.async.} =
  {.gcsafe.}:
    await fdSleep()
    resp responseBody

let app = newApp()
app.get("/", hello)
app.run()
