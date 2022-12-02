import std/asyncdispatch

proc fdSleep*(): Future[void] =
  var res = newFuture[void]()
  addTimer(10, true, proc (fd: AsyncFD): bool = res.complete(); return true)
  return res

var responseBody*: string
for i in 0 ..< 1:
  responseBody &= "abcdefghijklmnopqrstuvwxyz"
