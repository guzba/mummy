import mummy, mummy/routers, mummy/multipart

## This example shows how to handle a multipart/form-data POST body.

## Example curls to test multipart POST requests:
## curl -v -F key1="abc" -F key2="def" http://localhost:8080/multipart
## curl -v -F upload=@<FILE_PATH> http://localhost:8080/multipart

proc multipartHandler(request: Request) =
  let multipartEntries = request.decodeMultipart()
  for entry in multipartEntries:
    echo entry.name, ", has data? ", entry.data.isSome
    # If the entry has data:
    # if entry.data.isSome:
    #   let (start, last) = entry.data.get
    #   # You can copy out the data like this:
    #   request.body[start .. last]
    #   # Alternatively, you can use an openarray to avoid copying
    #   request.body.toOpenArray(start, last)

  var headers: HttpHeaders
  headers["Content-Type"] = "text/plain"
  request.respond(200, headers, "Multipart POST response")

var router: Router
router.post("/multipart", multipartHandler)

let server = newServer(router)
echo "Serving on http://localhost:8080"
server.serve(Port(8080))
