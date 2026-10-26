# clkp agent notes

Work in a lane (`~/agents/scratch/lane-new <lane>`); never edit `~/agents/scratch/ws`.
Run commands from the lane root (`<lane>/ws`); `<lane>` below is your lane name.

Build and test (quote the verdict line, never infer from a pipe):
- `~/agents/scratch/cbuild <lane> test -p clkp` — exit 101 at HEAD: lib
  `10 passed`; `--test live` `0 passed, 4 failed`: three fail in `enter` at
  `tests/live.rs:48` (`challenge` returns `Invalid`, cross-repo drift under
  test), one needs `VALKEY_URL` (`tests/live.rs:563`, CI disposable Valkey).
- `~/agents/scratch/cbuild <lane> fmt -p clkp -- --check` — must be clean
- `clippy -p clkp --all-targets -- -D warnings` is red at HEAD from upstream
  `ckmg` lints (unused `SigningPhase` import, dead `label`/`insert`), not this
  crate. Full gate (coverage) runs in CI only: `.ci/verify.sh`.

Land: `cargo fmt` in touched repos, rebase on main (never force-push),
`cbuild <lane> xtask land --dry`, then `xtask land`.

Invariants (rule -> enforcing test in `src/` unit tests, all passing):
- Index candidates equal an independent exhaustive Guard oracle
  -> `tests.rs::indexed_candidates_equal_an_independent_exhaustive_guard_oracle`
- Distance is Guard's, no approximation or ranking; same-member pairs refuse
  -> `tests.rs::distance_candidates_equal_exhaustive_guard_and_fixed_equatorial_oracle`
- Invalid types, private filters and missing detectors fail closed
  -> `tests.rs::invalid_types_private_filters_and_missing_contact_detector_fail_closed`
- Community/schema scope cannot cross index keys; encoding byte-identical
  -> `tests.rs::community_and_schema_scope_cannot_cross_index_keys`,
  `tests.rs::index_encoding_remains_byte_identical_across_digest_versions`
- Cursors opaque, bounded, expiring, deleted with attendance; resumption
  never extends expiry
  -> `cursor_tests::cursors_are_opaque_bound_expiring_and_deleted_with_attendance`
- Invalid/exhausted continuations refuse without eviction; token collision
  refuses without overwrite -> `cursor_tests::invalid_and_exhausted_continuations_refuse_without_eviction`,
  `cursor_tests::nonzero_token_collision_refuses_without_overwrite`
- Lookup narrows candidates, never authorizes; `forbid(unsafe_code)`
  (`src/lib.rs:3`); hostile wire refused (`deny_unknown_fields`,
  `src/cursor.rs`, `src/lookup.rs`)

Pointers: `src/lib.rs`, `src/cursor.rs`, `src/lookup.rs`, `tests/live.rs`,
`docs/CONTRACT.md`, `.ci/verify.sh`.
Commits: explicit paths, imperative, author per `~/agents/AGENT.md`; no AI trailers.
`publish=false`; LGPL-3.0-only WITH linking exception; no registry publication.
