---
"autoremediator": patch
---

A rollback that cannot put a file back now fails with a `rollback-failed` error listing the files,
instead of finishing as if the project had been restored. Every other file is still restored first,
and when the rollback was triggered by an error, that error stays in the message. The synchronous
restore now also refuses paths outside the project, as the asynchronous one already did, and a file in
a sibling directory that merely shares the project's path prefix is no longer tracked as part of it.
