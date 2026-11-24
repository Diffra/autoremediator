---
"autoremediator": patch
---

The `supply-chain` verification check no longer lets a dependency declaration it cannot read pass
unchecked. A change that points a dependency at a git or URL source, a package alias or a tag such as
`latest` has no registry version to look up, and used to be skipped, so it also skipped the age,
install-script and provenance rules. It now fails the check and names the declaration. `file:`,
`link:`, `portal:` and `workspace:` specs still pass, since nothing is fetched for them.
