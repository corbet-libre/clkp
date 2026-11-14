//! Hostile and degraded inputs to lookup: invalid limits, forged watch
//! cursors and a zero-lifetime evidence owner. Every case fails closed.
use super::*;

type Memory = cmmr::Memory<Time>;
type Board = Switchboard<Arc<Memory>, Time, Random>;
type Finder = Lookup<Arc<Memory>, Random>;
type Edit = Box<dyn FnOnce(&mut serde_json::Value)>;

fn memory(now: u64) -> (Time, Arc<Memory>) {
    let clock = Time(Arc::new(AtomicU64::new(now * 1000)));
    let store = Arc::new(
        cmmr::Memory::new(
            cmmr::Scope::new("garden", "forged").unwrap(),
            limits(),
            clock.clone(),
        )
        .unwrap(),
    );
    (clock, store)
}
fn record_key(cursor: &Cursor) -> String {
    format!("lkp_{}", data_encoding::HEXLOWER.encode(&cursor.0))
}
fn board_and_lookup(store: &Arc<Memory>, clock: &Time) -> (Board, Finder) {
    let board = Switchboard::new(
        store.clone(),
        clock.clone(),
        Random,
        "garden".into(),
        cswb::Limits {
            lease_ms: 60_000,
            publication_bytes: cpfl::MAX_PROFILE_BYTES,
            ciphertext_bytes: cpfl::MAX_PROFILE_BYTES,
        },
    )
    .unwrap();
    let lookup = Lookup::new(
        store.clone(),
        Random,
        LookupLimits {
            candidates: 5,
            publication_bytes: cpfl::MAX_PROFILE_BYTES * 5,
        },
    )
    .unwrap();
    (board, lookup)
}
fn watch_request<'a>(
    session: &'a Session,
    current: &'a Current,
    cursor: &'a Cursor,
) -> WatchRequest<'a> {
    WatchRequest {
        session,
        current,
        cursor,
    }
}
/// Store a copy of a genuine cursor record, edited, under a new token.
async fn forge(
    store: &Arc<Memory>,
    from: &Cursor,
    token: u8,
    edit: impl FnOnce(&mut serde_json::Value),
) -> Cursor {
    let record = store.get(&record_key(from)).await.unwrap().unwrap();
    let mut saved: serde_json::Value = serde_json::from_slice(&record.value).unwrap();
    edit(&mut saved);
    let cursor = Cursor([token; 16]);
    store
        .compare_exchange(&[cmmr::Write {
            expected: None,
            record: cmmr::Record {
                key: record_key(&cursor),
                generation: record.generation,
                revision: cmmr::Revision([token; 16]),
                deadline: record.deadline,
                value: serde_json::to_vec(&saved).unwrap(),
                indexes: vec![],
            },
        }])
        .await
        .unwrap();
    cursor
}

#[tokio::test]
async fn lookup_limits_are_validated() {
    let (_, store) = memory(2_000_000_000);
    for (candidates, publication_bytes) in [(0, 1), (256, 1), (1, 0)] {
        assert!(matches!(
            Lookup::new(
                store.clone(),
                Random,
                LookupLimits {
                    candidates,
                    publication_bytes
                }
            ),
            Err(LookupError::Invalid)
        ));
    }
    assert!(
        Lookup::new(
            store.clone(),
            Random,
            LookupLimits {
                candidates: 255,
                publication_bytes: 1
            }
        )
        .is_ok()
    );
}

#[tokio::test]
async fn forged_watch_windows_refuse_and_changed_rows_are_reported() {
    let now = 2_000_000_000;
    let (clock, store) = memory(now);
    let (board, lookup) = board_and_lookup(&store, &clock);
    let mut alice = Fixture::new("alice", 1, now).await;
    let mut phone = Fixture::with_device("bob", 1, now, vec![], 13).await;
    let mut laptop = Fixture::with_device("bob", 1, now, vec![], 14).await;
    let mut carol = Fixture::new("carol", 1, now).await;
    let (a, _) = enter(&board, &mut alice).await;
    enter(&board, &mut phone).await;
    enter(&board, &mut laptop).await;
    enter(&board, &mut carol).await;
    let ac = current(&board, &a, &mut alice, 1).await;
    // Both of bob's device rows sit on this one page and count once.
    let page = lookup
        .page(
            &board,
            request(&a, &ac, None, 5),
            &alice.verification(),
            &clean,
        )
        .await
        .unwrap();
    let mut members: Vec<_> = page.entries.iter().map(|e| e.member.as_str()).collect();
    members.sort();
    assert_eq!(members, ["bob", "carol"]);
    let refused: [(u8, Edit); 6] = [
        (1, Box::new(|v| v["watch"]["limit"] = 0.into())),
        (2, Box::new(|v| v["watch"]["limit"] = 6.into())),
        (3, Box::new(|v| v["watch"]["limit"] = 1.into())),
        (
            4,
            Box::new(|v| v["watch"]["seen"][0]["revision"] = 0.into()),
        ),
        (
            5,
            Box::new(|v| v["watch"]["seen"][0]["member"] = "!".into()),
        ),
        (
            6,
            Box::new(|v| {
                let first = v["watch"]["seen"][0]["member"].clone();
                v["watch"]["seen"][1]["member"] = first;
            }),
        ),
    ];
    for (token, edit) in refused {
        let forged = forge(&store, &page.watch, token, edit).await;
        assert!(matches!(
            lookup
                .watch(
                    &board,
                    watch_request(&a, &ac, &forged),
                    &alice.verification(),
                    &clean
                )
                .await,
            Err(LookupError::ResetRequired)
        ));
    }
    // A remembered row whose revision or digest no longer matches is reported
    // again instead of being treated as unchanged.
    let edits: [(u8, Edit); 2] = [
        (
            7,
            Box::new(|v| {
                let revision = v["watch"]["seen"][0]["revision"].as_u64().unwrap();
                v["watch"]["seen"][0]["revision"] = (revision + 1).into();
            }),
        ),
        (
            8,
            Box::new(|v| v["watch"]["seen"][0]["digest"] = serde_json::json!(vec![0u8; 32])),
        ),
    ];
    for (token, edit) in edits {
        let forged = forge(&store, &page.watch, token, edit).await;
        let delta = lookup
            .watch(
                &board,
                watch_request(&a, &ac, &forged),
                &alice.verification(),
                &clean,
            )
            .await
            .unwrap();
        assert_eq!(delta.upserts.len(), 1);
    }
    store.close();
}

struct ZeroLifetime;
impl AssociatedEvidence for ZeroLifetime {
    type Evidence = ();
    fn verify(&mut self, _: &cswb::VerifiedPresence) -> Result<Option<()>, LookupError> {
        Ok(Some(()))
    }
    fn current(&mut self, _: &()) -> Result<(), LookupError> {
        Ok(())
    }
    fn valid_until(&self, _: &()) -> u64 {
        0
    }
}

#[tokio::test]
async fn evidence_without_lifetime_is_refused() {
    let now = 2_000_000_000;
    let (clock, store) = memory(now);
    let (board, lookup) = board_and_lookup(&store, &clock);
    let mut alice = Fixture::new("alice", 1, now).await;
    let mut bob = Fixture::new("bob", 1, now).await;
    let (a, _) = enter(&board, &mut alice).await;
    enter(&board, &mut bob).await;
    let ac = current(&board, &a, &mut alice, 1).await;
    assert!(matches!(
        lookup
            .page_with(
                &board,
                request(&a, &ac, None, 5),
                &alice.verification(),
                &clean,
                &mut ZeroLifetime
            )
            .await,
        Err(LookupError::Associated)
    ));
    store.close();
}
