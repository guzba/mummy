const http = require('http')

var responseBody = "abcdefghijklmnopqrstuvwxyz"

const requestListener = function (req, res) {
    setTimeout(function() {
        res.writeHead(200)
        res.end(responseBody)
    }, 10)
}

const server = http.createServer(requestListener)
server.listen(8080)
