import ../common

# This is an extremely simple example logger. Works well during development.

proc echoLogger*(level: LogLevel, args: varargs[string]) =
  var logLen = 0
  for arg in args:
    logLen += arg.len
  var log = newStringOfCap(logLen)
  for arg in args:
    log.add(arg)
  echo log
