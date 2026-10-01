# Contract

Indexes are derived, typed and expiry bounded. Every read rechecks current generations, trust, reciprocal Guard match and deadlines. Cursors are opaque, bounded and community/requester/query/epoch/schema/generation/publication-revision bound. No ranking or private-field evaluation.

Projection prepares only Guard-validated public fields/rules, canonicalizes exact decimals through Schema, and computes scoped SHA-256 index keys with the maintained sha2 crate. Its exact reciprocal predicate delegates to cgrd::matches. The independent exhaustive oracle covers pairs, ranges, choices, optional values, numeric spellings and scope changes; there is no retained roster.

Cursors use random opaque tokens over one authoritative volatile cmmr Store. Resumption cannot extend expiry. Changing any context field, departure, expiry or unavailable/corrupt storage refuses or requires reset. Revision changes force reset even when the query string happens to stay the same. The caller derives context from current verified attendance; a cursor is never admission or disclosure authority.

Implementation and acceptance remain incomplete: live index publication after Switchboard CAS, current authorized pages/deltas, both-party rechecks and ciphertext disclosure must consume actual current G1/G2/G3/Profile capabilities. No optional trust check or synthetic acceptance replaces those ports.
