---
"cojson": patch
---

`waitForSync` and `waitForAllCoValuesSync` no longer hang until their timeout on a CoValue that no peer has. The wait ends once its load ends unavailable.
