when (NimMajor, NimMinor, NimPatch) < (2, 0, 0):
  --threads:on
  --mm:orc

when defined(feature.mummy.testing) and
    not defined(chroniclers.logBackend) and
    not defined(chroniclersLogBackend) and
    not defined(chroniclersBackendModule):
  switch("define", "chroniclers.logBackend=chronicles")
