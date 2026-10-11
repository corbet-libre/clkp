# Contract

Indexes are derived, typed and expiry bounded. Every read rechecks current generations, trust, reciprocal Guard match and deadlines. Cursors are opaque, bounded and community/requester/query/epoch/schema/generation/publication-revision bound. No ranking or private-field evaluation.

Projection prepares only Guard-validated public fields/rules, canonicalizes exact decimals through Schema, and computes scoped SHA-256 index keys with the maintained sha2 crate. Its exact reciprocal predicate delegates to cgrd::matches. The independent exhaustive oracle covers pairs, ranges, choices, optional values, numeric spellings and scope changes; there is no retained roster.

Cursors use random opaque tokens over one authoritative volatile cmmr Store. Resumption cannot extend expiry. Changing any context field, departure, expiry or unavailable/corrupt storage refuses or requires reset. Revision changes force reset even when the query string happens to stay the same. The caller derives context from current verified attendance; a cursor is never admission or disclosure authority.

The candidate Lookup implementation now reads bounded live Switchboard rows,
checks both real Guard participants, and atomically confirms every selected row
plus the requester before disclosing original signed bytes. Cursor context also
binds the current trust revision and requested page bound. Ciphertext retrieval
uses the identical two-party check and exact requested Profile revision. No
accepting callback or serialized capability is used. Real Memory/Valkey scenarios
are written for blocks, replacement, departure, revocation and stale cursors;
this successor has not yet compiled. Incremental deltas remain unfinished.

Distance predicates delegate to the current Guard DistanceRange API. Lookup
performs no spatial approximation, distance calculation or ranking. A fixed
equatorial-band oracle and independently constructed exhaustive Guard participants
check all144 ordered pairs; same-member pairs refuse, as required by Guard.

G1 credential/Guard checks belong to `cgrd::check_published`, referenced through
Charter and Assurance. Envoy (`cnvy`) fetches/follows feeds; it does not verify
authority. Current Profile device authority and per-request possession must be composed
with those owner checks. Complete Forum admission additionally requires the
current epoch record/minimum-frontier relation. Gather supplies the genuine
accounting owner; Lookup's original G1/device methods alone do not establish it.
Lookup never imports accounting business logic or constructs its evidence.

The polling successor adds an opaque `Matches.watch` cursor for ONE bounded
candidate window. `watch(WatchRequest)` returns changed publications, removed
previously visible IDs, a new polling cursor and current pagination cursor.
Each poll obtains current requester/candidates from Switchboard, repeats original
two-way Guard, and atomically confirms all disclosed rows together. The retained
cursor contains only original start/limit and seen ID/revision/SHA256 tuples,
never copied profiles or a full match list. Its original requester expiry and
scope/revision/query/trust binding cannot be extended by polling. Changes outside
that bounded window appear through normal pages, not an unbounded feed. Context,
requester revision, schema, policy or generation changes require reset. Removals
mean leaving that displayed window, not a claim that the member left the service.
Memory/Valkey tests now include unchanged/add/update/remove, foreign cursor and
heartbeat reset. These successor vectors are written, not executed.

`page_with`, `watch_with` and `ciphertext_with` require a caller-owned concrete
`AssociatedEvidence` implementation. Gather supplies its native accounting owner;
no request chooses that implementation. Missing candidate evidence is omitted
before seen state or output is built, while missing requester evidence refuses.
Actual owner capabilities remain held through all awaits and the final atomic
presence cut. The owner rechecks both its authority and the exact row's exclusive
deadline at that cut. Every retained capability shortens cursor expiry. The
checked cursor query domain differs from the original G1-only domain, preventing
old observations from becoming complete-admission observations or removals.
The original opaque storage continuation still advances over bounded scanned
nonmatches; it conveys no match count or admission authority. Only checked
selected IDs enter watch observations. No accepting default verifier is supplied.

## Associated-owner boundary tests

The associated test child uses actual csgn signatures and the maintained
KeyRing verifier over auxiliary fixture publications identifying the exact
committed Switchboard Binding and revision. Its retained evidence contains the
owner-verified publication, original signed bytes and row deadline; it rechecks
signature currentness, its clock floor and exclusive row expiry after awaits.
This private test format qualifies the generic owner boundary only. It is not
accounting evidence, a native proof substitute or complete Forum admission.

The genuine G1/profile/device setup remains unchanged except for required current
Credential purpose/action fields. Tests keep legacy and associated page/watch
cursor domains separate, omit bad/missing/expired candidate evidence before
entries or seen state, bind observation expiry to retained evidence, and ensure
later removal cannot introduce a never-observed candidate. A real Memory Store
wrapper advances the auxiliary owner's clock after each actual store operation
in page, watch and ciphertext reads; signature expiry and exact row expiry while
signatures remain valid each refuse the composed return. These source scenarios
have not been executed. Concrete native accounting composition belongs to
Gather's separate owner integration tests.
