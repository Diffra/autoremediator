---
"autoremediator": patch
---

`diff` (the delta scan) no longer reads a damaged `package-lock.json` or `pnpm-lock.yaml` as an empty
lockfile. A changed lockfile that is not valid JSON or YAML now stops the scan with an error that names
the file, instead of reporting every package as added or removed.
