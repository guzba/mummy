type
  MummyError* = object of CatchableError

  HttpVersion* = enum
    Http10, Http11

  LogLevel* = enum
    DebugLevel, InfoLevel, ErrorLevel

  LogHandler* = proc(level: LogLevel, args: varargs[string]) {.gcsafe.}

proc echoLogger*(level: LogLevel, args: varargs[string]) =
  ## This is a simple echo logger.
  if args.len == 1:
    echo args[0]
  else:
    var lineLen = 0
    for arg in args:
      lineLen += arg.len
    var line = newStringOfCap(lineLen)
    for arg in args:
      line.add(arg)
    echo line
