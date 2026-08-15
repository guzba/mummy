import mummy
import std/[atomics, locks, os, tables]

type Upload = object
  file: File
  path: string

var
  uploadLock: Lock
  uploads {.guard: uploadLock.}: Table[RequestBodyStream, Upload]
  nextUploadId: Atomic[int]

initLock(uploadLock)
createDir("uploads")

proc takeUpload(stream: RequestBodyStream): Upload {.gcsafe.} =
  {.gcsafe.}:
    withLock uploadLock:
      if stream in uploads:
        result = uploads[stream]
        uploads.del(stream)

proc discardUpload(stream: RequestBodyStream) {.gcsafe.} =
  let upload = takeUpload(stream)
  if upload.file != nil:
    upload.file.close()
    removeFile(upload.path)

proc handler(request: Request) =
  request.respond(404)

proc requestBodyHandler(
  request: Request,
  stream: RequestBodyStream,
  event: RequestBodyEvent
) {.gcsafe.} =
  case event.kind
  of RequestBodyOpen:
    if request.httpMethod != "PUT" or request.path != "/upload":
      # Keep the traditional request.body behavior for all other routes.
      discard stream.buffer()
      return

    let id = nextUploadId.fetchAdd(1, moRelaxed)
    let path = "uploads" / ("upload-" & $id & ".bin")
    try:
      let upload = Upload(file: open(path, fmWrite), path: path)
      {.gcsafe.}:
        withLock uploadLock:
          uploads[stream] = upload
      discard stream.accept()
    except IOError:
      discard stream.reject(statusCode = 500, body = "Could not open upload")
  of RequestBodyChunk:
    var upload: Upload
    {.gcsafe.}:
      withLock uploadLock:
        if stream in uploads:
          upload = uploads[stream]
    if upload.file == nil:
      discard stream.reject(statusCode = 500)
      return
    try:
      upload.file.write(event.data)
    except IOError:
      discardUpload(stream)
      discard stream.reject(statusCode = 500, body = "Could not write upload")
  of RequestBodyEnd:
    let upload = takeUpload(stream)
    if upload.file == nil:
      request.respond(500)
      return
    upload.file.close()
    request.respond(201, body = upload.path)
  of RequestBodyError:
    # The client disconnected or the server is shutting down.
    discardUpload(stream)

let server = newServer(
  handler,
  maxBodyLen = 1024 * 1024 * 1024,
  requestBodyHandler = requestBodyHandler,
  requestBodyChunkSize = 64 * 1024
)

echo "Upload with:"
echo "curl --data-binary @my-file.bin -X PUT http://localhost:8080/upload"
server.serve(Port(8080))
