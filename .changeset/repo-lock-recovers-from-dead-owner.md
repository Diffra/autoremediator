---
"autoremediator": patch
---

The repository lock no longer blocks every later run after a crash. The lock directory now records the
process that holds it, and a lock whose owner process has exited on this machine is taken over instead
of being waited on until it times out. A failure to create the lock directory (no permission, no space)
is reported at once instead of being retried until the timeout.
