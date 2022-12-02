import prologue, wrk_shared

proc hello*(ctx: Context) {.async.} =
  {.gcsafe.}:
    await fdSleep()
    resp responseBody

let app = newApp()
app.gScope.settings.debug = false
app.get("/", hello)
app.run()
