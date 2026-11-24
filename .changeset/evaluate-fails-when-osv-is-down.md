---
"autoremediator": patch
---

`evaluatePackage` (and `autoremediator evaluate`, the MCP `evaluatePackage` tool and `diff`, which
relies on it) no longer reports "no known vulnerabilities, safe to install" when it could not ask OSV.
A failed OSV lookup now throws an `UpstreamError` (code `upstream-unavailable`), and a name that is not
a valid npm package name, such as an empty string, is rejected before any lookup.
