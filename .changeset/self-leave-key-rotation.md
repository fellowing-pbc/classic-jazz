---
"cojson": patch
---

A member who revokes themself no longer keeps the group's read key. An admin or manager node rotates the key when it sees a revoked member who still holds it: when the revocation arrives, and when the group loads.
