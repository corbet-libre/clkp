# clkp — Lookup

Implementation in progress. Admission is unavailable until current trust, public-record and device-authority capabilities are integrated.

## Scope

Derive typed indexes and bounded reciprocal match pages from current Switchboard entries. Guard owns rule evaluation; Lookup owns neither identity nor a second listing.

Return bounded reciprocal matches only; preserve exact values and delegate all rule semantics, including distance, to Guard. Expired/revoked/withdrawn entries are ineligible before cleanup. Guard supplies distance evaluation and Schema supplies read-only validation types. Current live authority and ciphertext disclosure integration remain unavailable; no ranking, match tokens, full-roster delivery or profile keys.

## Dependencies and validation

Reuse the existing volatile storage port and Guard rather than duplicate their mechanisms. CI resolves one lock snapshot and gates stable checks plus exact line and branch coverage. Passing a storage transition test does not establish admission integration.
