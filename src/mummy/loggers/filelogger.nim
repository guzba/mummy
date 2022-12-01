import ../common

type
  FileLoggerObj = object

  FileLogger* = ptr FileLoggerObj

proc newFileLogger*(filePath: string): FileLogger =
  result = cast[FileLogger](allocShared0(sizeof(FileLoggerObj)))

proc log*(
  logger: FileLogger,
  level: LogLevel,
  args: sink varargs[string, `$`]
) {.gcsafe.} =
  echo "file logger not implemented yet"

proc debug*(
  logger: FileLogger,
  args: sink varargs[string, `$`]
) {.inline, gcsafe.} =
  logger.log(DebugLevel, args)

proc info*(
  logger: FileLogger,
  args: sink varargs[string, `$`]
) {.inline, gcsafe.} =
  logger.log(InfoLevel, args)

proc error*(
  logger: FileLogger,
  args: sink varargs[string, `$`]
) {.inline, gcsafe.} =
  logger.log(ErrorLevel, args)

proc close*(logger: FileLogger) {.gcsafe.} =
  discard
