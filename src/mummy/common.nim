type
  MummyError* = object of CatchableError

  HttpVersion* = enum
    Http10, Http11

  LogLevel* = enum
    DebugLevel, InfoLevel, ErrorLevel

  LogHandler* = proc(level: LogLevel, args: varargs[string]) {.gcsafe.}

proc echoLogger*(level: LogLevel, args: varargs[string]) =
  ## This is an extremely simple logger. Works well during development.
  ## Check out the file logging example in the examples/ dir for an upgrade.
  var lineLen = 0
  for arg in args:
    lineLen += arg.len
  var line = newStringOfCap(lineLen)
  for arg in args:
    line.add(arg)
  echo line
