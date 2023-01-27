import common, std/deques, std/locks

## Since Mummy is a multithreaded server, we need an easy way to handle incoming
## logs from many threads.
##
## FileLogger queues incoming logs from any number of threads, then an internal
## writer thread appends them to a file.
##
## Error logs skip the queue and are flushed directly by the calling thread.

type
  FileLoggerObj = object
    file: File
    queueLock, writeLock: Lock
    cond: Cond
    destroyCalled: bool
    writerThread: Thread[FileLogger]
    queue: Deque[string]

  FileLogger* = ptr FileLoggerObj
    ## FileLogger is a thread-safe log writer that appends lines to a file.

proc log*(
  logger: FileLogger,
  level: LogLevel,
  args: varargs[string, `$`]
) {.raises: [], gcsafe.} =
  ## Adds a log entry to the queue. Log entries are taken from the queue
  ## and written to the file by an internal thread.
  ## Error logs skip the queue and are flushed directly by the calling thread.
  var lineLen = 1
  for arg in args:
    lineLen += arg.len
  var line = newStringOfCap(lineLen)
  for arg in args:
    line.add(arg)
  line.add('\n')
  if level == ErrorLevel:
    try:
      withLock logger.writeLock:
        write(logger.file, line)
        flushFile(logger.file)
    except IOError:
      discard # What can we do?
  else:
    var queueWasEmpty: bool
    withLock logger.queueLock:
      queueWasEmpty = logger.queue.len == 0
      logger.queue.addLast(move line)
    if queueWasEmpty:
      signal(logger.cond)

proc debug*(
  logger: FileLogger,
  args: varargs[string, `$`]
) {.raises: [], inline, gcsafe.} =
  ## Adds a debug log entry to the queue. Log entries are taken from the queue
  ## and written to the file by an internal thread.
  logger.log(DebugLevel, args)

proc info*(
  logger: FileLogger,
  args: varargs[string, `$`]
) {.raises: [], inline, gcsafe.} =
  ## Adds an info log entry to the queue. Log entries are taken from the queue
  ## and written to the file by an internal thread.
  logger.log(InfoLevel, args)

proc error*(
  logger: FileLogger,
  args: varargs[string, `$`]
) {.raises: [], inline, gcsafe.} =
  ## Error logs skip the queue and are flushed directly by the calling thread.
  logger.log(ErrorLevel, args)

proc destroy(logger: FileLogger) =
  withLock logger.queueLock:
    logger.destroyCalled = true
  signal(logger.cond)
  joinThreads(logger.writerThread)
  close(logger.file)
  deinitLock(logger.queueLock)
  deinitLock(logger.writeLock)
  deinitCond(logger.cond)
  `=destroy`(logger[])
  deallocShared(logger)

proc close*(logger: FileLogger) {.raises: [], gcsafe.} =
  ## Cleanly stops and deallocates the logger.
  ## Queued log lines will be written before this returns.
  logger.destroy()

proc writerProc(logger: FileLogger) {.raises: [].} =
  var
    logLines: seq[string]
    exitLoop: bool
  while true:
    acquire(logger.queueLock)

    while logger.queue.len == 0 and not logger.destroyCalled:
      wait(logger.cond, logger.queueLock)

    exitLoop = logger.destroyCalled

    while logger.queue.len > 0:
      logLines.add(logger.queue.popFirst)

    release(logger.queueLock)

    if logLines.len > 0:
      try:
        withLock logger.writeLock:
          for line in logLines:
            write(logger.file, line)
          flushFile(logger.file)
      except:
        discard # What can we do?
      logLines.setLen(0)

    if exitLoop:
      return

proc newFileLogger*(
  filePath: string
): FileLogger {.raises: [IOError, ResourceExhaustedError].} =
  result = cast[FileLogger](allocShared0(sizeof(FileLoggerObj)))
  result.file = open(filePath, fmAppend)
  initLock(result.queueLock)
  initLock(result.writeLock)
  initCond(result.cond)
  try:
    createThread(result.writerThread, writerProc, result)
  except ResourceExhaustedError as e:
    result.destroy()
    raise e
