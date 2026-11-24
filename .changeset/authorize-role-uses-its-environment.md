---
"autoremediator": patch
---

`authorizeRole` now looks a bearer token up in the environment it was given, not in the process
environment. When it was called with explicit settings and the process had none, every token resolved to
`admin`. The servers call it with the process environment, so they were not affected.
