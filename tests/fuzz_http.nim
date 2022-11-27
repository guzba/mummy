import mummy {.all.}, std/random, std/strutils

randomize()

proc randomWhitespace(): string =
  let len = rand(0 ..< 10)
  for i in 0 ..< len:
    result &= ' '

block:
  echo "Fuzzing headerContainsToken"

  proc randomToken(): string =
    let len = rand(0 ..< 10)
    for i in 0 ..< len:
      var c: char
      while true:
        c = rand(33 .. 126).char
        if c != 44.char:
          break
      result &= c.char

  for i in 0 ..< 1000:
    var tokens: seq[seq[string]]
    tokens.setLen(10)

    var headers: HttpHeaders
    for i in 0 ..< 10:
      let numTokens = rand(0 ..< 10)
      if numTokens > 0:
        var v: string
        for j in 0 ..< numTokens:
          let token = randomToken()
          tokens[i].add(token)
          if j > 0:
            v &= randomWhitespace() & ','
          v &= randomWhitespace() & token
        headers[$i] = v
      else:
        let v = randomToken()
        tokens[i].add(v)
        headers[$i] = v

    for i in 0 ..< tokens.len:
      for j in 0 ..< tokens[i].len:
        if tokens[i][j].len > 0 and
          not headers.headerContainsToken($i, toLowerAscii(tokens[i][j])):
          echo "header: ", headers[$i]
          echo "token: ", tokens[i][j]
          doAssert false
