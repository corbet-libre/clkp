# clkp — Lookup

Implementation in progress. Admission is unavailable until current trust, public-record and device-authority capabilities are integrated.

## Scope

### Purpose

clkp finds candidates for a member efficiently and keeps the live match list current over a RAM-only table of typed attributes.

### Owns

- Derived typed indexes over committed Switchboard entries and candidate selection, with reciprocal two-way evaluation through cgrd.
- Returns only two-way matches.
- A paged and incremental match feed that reports arrivals and departures.
- Serving a stored ciphertext only to a currently authorized reader under the current pair check.
- Index storage through cvtl; the device-side counterpart is csrh Search, which holds the member cursor and local recheck.

### Never

- Holds no second listing and never sends the full match list to a device.
- Reveals no blocked owners, evaluates no private fields, ranks nothing by recorded activity, and issues no match tokens.
- Coarsens no values: exact numbers only, with ranges only in rules.
- Relays no profile keys and performs no key exchange.
- Keeps no search history and no contact graph.

### States

Empty to Indexed; subscriptions move from an initial page to following a cursor, requiring a reset on gaps or schema changes, then closed. Expired, withdrawn, departed, or revoked entries are ineligible before index cleanup.

### Test obligations

- Real two-way matches over exact numbers, ranges, choices, and blocks; index candidates equal independent exhaustive evaluation.
- Page bounds and cursors bind requester, query, epoch, and generation; additions, updates, removals, and gaps give deterministic results.
- Departure, block, or revocation between page and ciphertext read refuses access, and a blocked member never sees the blocker.
- Large forums keep pages bounded so a device never receives the whole list.

## Dependencies and validation

Reuse the existing volatile storage port and Guard rather than duplicate their mechanisms. CI resolves one lock snapshot and gates stable checks plus exact line and branch coverage. Passing a storage transition test does not establish admission integration.
