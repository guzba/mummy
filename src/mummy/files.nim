import ../mummy, std/locks, std/os, std/tables

type
  FileStreamState = object
    file: File
    chunkSize: int

var
  fileStreamsLock: Lock
  fileStreams {.guard: fileStreamsLock.}: Table[ResponseStream, FileStreamState]

initLock(fileStreamsLock)

proc closeFileStream(stream: ResponseStream): bool {.raises: [], gcsafe.} =
  var
    file: File
    found: bool

  {.cast(gcsafe).}:
    withLock fileStreamsLock:
      try:
        file = fileStreams[stream].file
        fileStreams.del(stream)
        found = true
      except KeyError:
        discard

  if found:
    try:
      file.close()
    except IOError:
      discard

  result = found

proc sendNextFileChunk(stream: ResponseStream): bool {.raises: [], gcsafe.} =
  var state: FileStreamState

  {.cast(gcsafe).}:
    withLock fileStreamsLock:
      try:
        state = fileStreams[stream]
        result = true
      except KeyError:
        return false

  var data = newString(state.chunkSize)
  var bytesRead: int

  try:
    bytesRead = state.file.readChars(data.toOpenArray(0, data.high))
  except IOError:
    discard closeFileStream(stream)
    stream.close()
    return true

  if bytesRead == 0:
    discard closeFileStream(stream)
    stream.close()
    return true

  data.setLen(bytesRead)
  if not stream.write(move data):
    discard closeFileStream(stream)
    stream.close()

proc handleFileStream*(
  stream: ResponseStream,
  event: StreamEvent
): bool {.raises: [], gcsafe.} =
  ## Handles stream events for files opened with `respondFile`.
  case event:
  of StreamOpen, StreamWritable:
    result = sendNextFileChunk(stream)
  of StreamError, StreamClosed:
    result = closeFileStream(stream)

proc fileStreamHandler*(
  stream: ResponseStream,
  event: StreamEvent
) {.raises: [], gcsafe.} =
  ## A complete stream handler for servers that only use `respondFile`.
  discard handleFileStream(stream, event)

proc respondFile*(
  request: Request,
  path: string,
  contentType = "application/octet-stream",
  statusCode = 200,
  headers: sink HttpHeaders = emptyHttpHeaders(),
  chunkSize = 64 * 1024
): bool {.raises: [], gcsafe.} =
  ## Streams a file with response-stream backpressure.
  ##
  ## Returns false and sends a 404 response if the file cannot be opened.
  var file: File
  try:
    if not fileExists(path):
      request.respond(404)
      return false
    file = open(path, fmRead)
  except CatchableError:
    request.respond(404)
    return false

  if contentType.len > 0:
    headers["Content-Type"] = contentType

  let stream = request.respondStream(statusCode, headers, start = false)

  {.cast(gcsafe).}:
    withLock fileStreamsLock:
      fileStreams[stream] = FileStreamState(
        file: file,
        chunkSize: max(chunkSize, 1)
      )

  stream.start()
  result = true
