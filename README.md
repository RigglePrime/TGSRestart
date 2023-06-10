# TGSRestart

Simple program that does the following:
- Disables and kills the TG server service, orphaning DD
- Gets the command line params of all DD processes, parses them and writes relevant info to its Instance.json
- Re-enables the service (with the same startup type) and tries to start it back up
