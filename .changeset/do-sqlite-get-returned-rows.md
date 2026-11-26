---
"@fellowing/cojson-storage-do-sqlite": patch
---

`DurableObjectSqlDriver.get` returns the first row the query returned, or undefined. It used to check `rowsRead`, which counts rows SQLite read, so a query that read rows but returned none threw. That made storing a CoValue whose header was already stored fail, and its new transactions were not stored.
