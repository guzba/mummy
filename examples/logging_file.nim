import mummy, mummy/fileloggers, std/os

## This example shows filtering logs based on level and then writing them
## to a file using Mummy's FileLogger.
##
## The log file is created based on current PID and placed in the current
## working directory. This ensure each run gets a new log file automatically.
##
## You can monitor the logs with: tail -f <logfile>

let
  pid = getCurrentProcessId()
  cwd = getCurrentDir()
  logFile = joinPath(cwd, $pid & ".txt")
  logger = newFileLogger(logFile)

echo "Logging to " & logFile

proc logHandler(level: LogLevel, args: varargs[string]) =
  # Filter logs based on level before calling the logger
  if level >= InfoLevel:
    logger.log(level, args)

proc handler(request: Request) =
  logger.debug(request.httpMethod, " ", request.uri)
  if request.uri == "/info":
    logger.info("Info!")
  elif request.uri == "/error":
    logger.error("Error!")
  request.respond(200)

let server = newServer(handler, logHandler = logHandler)
echo "Serving on http://localhost:8080"
server.serve(Port(8080))
