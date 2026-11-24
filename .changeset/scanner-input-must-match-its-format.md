---
"autoremediator": patch
---

A scanner file that does not match its format is now an error that names the file and the field,
instead of a successful run with zero findings. npm audit JSON must have a top-level `vulnerabilities`
object, SARIF must have `runs`, and Yarn audit output must contain an `auditAdvisory` or
`auditSummary` record. Clean reports in those formats are still accepted.
