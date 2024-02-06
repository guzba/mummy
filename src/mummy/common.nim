import std/typetraits

type
  MummyError* = object of CatchableError

  HttpVersion* = enum
    Http10, Http11

  LogLevel* = enum
    DebugLevel, InfoLevel, ErrorLevel

  LogHandler* = proc(level: LogLevel, args: varargs[string]) {.gcsafe.}

  PathParams* = distinct seq[(string, string)]

converter toBase*(pathParams: var PathParams): var seq[(string, string)] =
  pathParams.distinctBase

converter toBase*(pathParams: PathParams): lent seq[(string, string)] =
  pathParams.distinctBase

proc `[]`*(pathParams: PathParams, key: string): string =
  ## Returns the value for key, or an empty string if the key is not present.
  for (k, v) in pathParams.toBase:
    if k == key:
      return v

proc `[]=`*(pathParams: var PathParams, key, value: string) =
  ## Sets the value for the key. If the key is not present, this
  ## appends a new key-value pair to the end.
  for pair in pathParams.mitems:
    if pair[0] == key:
      pair[1] = value
      return
  pathParams.add((key, value))

proc contains*(pathParams: PathParams, key: string): bool =
  for pair in pathParams:
    if pair[0] == key:
      return true

proc getOrDefault*(pathParams: PathParams, key, default: string): string =
  if key in pathParams: pathParams[key] else: default

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
