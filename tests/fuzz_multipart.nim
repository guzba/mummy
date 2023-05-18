import mummy, mummy/multipart

let valid = "--123\r\nContent-Disposition: form-data; name=\"abc\";filename=\"file.txt\";\r\nContent-Type: text/plain\r\n\r\ndef\r\n--123\r\nContent-Disposition: form-data; name=\"ghi\"\r\nDummy-Header-1: 1\r\nDummy-Header-2: 2\r\nBroken-Header\r\n\r\njkl\r\n--123--"

let request = cast[Request](allocShared0(sizeof(RequestObj)))
request.headers["Content-Type"] = "multipart/form-data; boundary=123"

for i in 0 ..< valid.len:
  request.body = valid[0 .. i]
  try:
    discard request.decodeMultipart()
  except:
    discard

for i in 0 ..< valid.len:
  request.body = valid[i .. ^1]
  try:
    discard request.decodeMultipart()
  except:
    discard
