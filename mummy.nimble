version     = "0.5.1"
author      = "Ryan Oldenburg"
description = "Multithreaded HTTP + WebSocket server"
license     = "MIT"

srcDir = "src"

requires "nim >= 2.0.0"
requires "zippy >= 0.10.9"
requires "webby >= 0.2.1"
requires "crunchy >= 0.1.11"
requires "chroniclers >= 0.3.0"

feature "chronicles":
  requires "chroniclers[chronicles] >= 0.3.0"

feature "testing":
  requires "chronicles >= 0.12.3"
  requires "whisky"
  requires "jsony"
