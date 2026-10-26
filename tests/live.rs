mod support;
use clkp::*;
use cmmr::{Clock, Store};
use cswb::{Current, Session, Switchboard, Tokens};
use ed25519_dalek::Signer as _;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use support::*;

#[derive(Clone)]
struct Time(Arc<AtomicU64>);
impl Clock for Time {
    fn now(&self) -> Result<u64, cmmr::Error> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}
struct Random;
impl Tokens for Random {
    fn next(&self) -> Result<[u8; 16], cswb::Error> {
        use ckmg::Entropy;
        let mut out = [0; 16];
        ckmg::SystemEntropy
            .fill(&mut out)
            .map_err(|_| cswb::Error::Invalid)?;
        Ok(out)
    }
}
fn limits() -> cmmr::Limits {
    cmmr::Limits {
        records: 96,
        value_bytes: 262144,
        batch: 4,
        indexes_per_record: 4,
        page: 8,
        ttl_ms: 600000,
    }
}
async fn enter<S: Store, C: Clock>(
    board: &Switchboard<S, C, Random>,
    fixture: &mut Fixture,
) -> (Session, cswb::Live) {
    let publication = fixture.publication.clone();
    let challenge = board
        .challenge(ORIGIN, &publication, &fixture.verification(), &clean)
        .await
        .unwrap();
    let signature = fixture
        .device
        .sign(&cswb::challenge_message(
            ORIGIN,
            "garden",
            &challenge,
            &publication.signed,
        ))
        .to_bytes();
    let admission = board
        .admit(
            cswb::EntryProof {
                origin: ORIGIN,
                challenge: &challenge,
                signature: &signature,
                publication: &publication,
            },
            &fixture.verification(),
            &clean,
        )
        .await
        .unwrap();
    board.enter(admission).await.unwrap()
}
async fn current<S: Store, C: Clock>(
    board: &Switchboard<S, C, Random>,
    session: &Session,
    fixture: &mut Fixture,
    nonce: u8,
) -> Current {
    let nonce = [nonce; 16];
    let possession = cswb::Possession {
        nonce,
        signature: fixture
            .device
            .sign(&cswb::request_message(
                ORIGIN, "search", session, &nonce, b"query",
            ))
            .to_bytes()
            .to_vec(),
    };
    board
        .authorize(
            cswb::RequestProof {
                origin: ORIGIN,
                session,
                action: "search",
                body: b"query",
                possession: &possession,
            },
            &fixture.verification(),
            &clean,
        )
        .await
        .unwrap()
}
fn request<'a>(
    session: &'a Session,
    current: &'a Current,
    cursor: Option<&'a Cursor>,
    limit: usize,
) -> PageRequest<'a> {
    PageRequest {
        session,
        current,
        cursor,
        limit,
    }
}

// Both actual adapters execute this scenario with real issuer and device
// signatures. Lower-level capabilities are reused to isolate storage races;
// the HTTP controller must authorize each incoming operation separately.
async fn round_trip<S: Store, C: Clock + Clone>(store: Arc<S>, clock: C, now: u64) {
    let board = Switchboard::new(
        store.clone(),
        clock,
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
            candidates: 3,
            publication_bytes: cpfl::MAX_PROFILE_BYTES * 3,
        },
    )
    .unwrap();
    let mut alice = Fixture::new("alice", 1, now).await;
    let mut bob = Fixture::new("bob", 1, now).await;
    let mut carol = Fixture::new("carol", 1, now).await;
    let (a, al) = enter(&board, &mut alice).await;
    let (b, bl) = enter(&board, &mut bob).await;
    let (c, cl) = enter(&board, &mut carol).await;
    let ac = current(&board, &a, &mut alice, 1).await;
    let bc = current(&board, &b, &mut bob, 2).await;
    let first = lookup
        .page(
            &board,
            request(&a, &ac, None, 1),
            &alice.verification(),
            &clean,
        )
        .await
        .unwrap();
    assert!(first.entries.is_empty());
    let next = first.next.unwrap();
    let second = lookup
        .page(
            &board,
            request(&a, &ac, Some(&next), 1),
            &alice.verification(),
            &clean,
        )
        .await
        .unwrap();
    assert_eq!(second.entries.len(), 1);
    assert_eq!(second.entries[0].member, "bob");
    assert_eq!(second.entries[0].publication, bob.publication.signed);
    let unchanged = lookup
        .watch(
            &board,
            WatchRequest {
                session: &a,
                current: &ac,
                cursor: &second.watch,
            },
            &alice.verification(),
            &clean,
        )
        .await
        .unwrap();
    assert!(unchanged.upserts.is_empty() && unchanged.removed.is_empty());
    let mut aaron = Fixture::new("aaron", 1, now).await;
    let (temporary, _) = enter(&board, &mut aaron).await;
    let added = lookup
        .watch(
            &board,
            WatchRequest {
                session: &a,
                current: &ac,
                cursor: &first.watch,
            },
            &alice.verification(),
            &clean,
        )
        .await
        .unwrap();
    assert!(added.removed.is_empty());
    assert_eq!(added.upserts.len(), 1);
    assert_eq!(added.upserts[0].member, "aaron");
    board.depart(&temporary).await.unwrap();
    let left = lookup
        .watch(
            &board,
            WatchRequest {
                session: &a,
                current: &ac,
                cursor: &added.watch,
            },
            &alice.verification(),
            &clean,
        )
        .await
        .unwrap();
    assert!(left.upserts.is_empty());
    assert_eq!(left.removed, ["aaron"]);
    assert!(matches!(
        lookup
            .watch(
                &board,
                WatchRequest {
                    session: &b,
                    current: &bc,
                    cursor: &second.watch
                },
                &bob.verification(),
                &clean
            )
            .await,
        Err(LookupError::ResetRequired)
    ));
    assert!(matches!(
        lookup
            .watch(
                &board,
                WatchRequest {
                    session: &a,
                    current: &ac,
                    cursor: &next
                },
                &alice.verification(),
                &clean
            )
            .await,
        Err(LookupError::Cursor(CursorError::ResetRequired))
    ));
    assert!(matches!(
        lookup
            .page(
                &board,
                request(&b, &bc, Some(&next), 1),
                &bob.verification(),
                &clean
            )
            .await,
        Err(LookupError::Cursor(CursorError::ResetRequired))
    ));
    assert!(matches!(
        lookup
            .page(
                &board,
                request(&a, &ac, Some(&next), 2),
                &alice.verification(),
                &clean
            )
            .await,
        Err(LookupError::Cursor(CursorError::ResetRequired))
    ));
    assert_eq!(
        lookup
            .ciphertext(
                &board,
                request(&a, &ac, None, 1),
                ("bob", 1),
                &alice.verification(),
                &clean
            )
            .await
            .unwrap(),
        bob.publication.ciphertext
    );
    assert!(matches!(
        lookup
            .ciphertext(
                &board,
                request(&a, &ac, None, 1),
                ("bob", 2),
                &alice.verification(),
                &clean
            )
            .await,
        Err(LookupError::ResetRequired)
    ));
    assert!(matches!(
        lookup
            .ciphertext(
                &board,
                request(&a, &ac, None, 1),
                ("alice", 1),
                &alice.verification(),
                &clean
            )
            .await,
        Err(LookupError::ResetRequired)
    ));
    for size in [0, 4] {
        assert!(matches!(
            lookup
                .page(
                    &board,
                    request(&a, &ac, None, size),
                    &alice.verification(),
                    &clean
                )
                .await,
            Err(LookupError::Invalid)
        ));
    }
    let bounded = Lookup::new(
        store.clone(),
        Random,
        LookupLimits {
            candidates: 3,
            publication_bytes: 1,
        },
    )
    .unwrap();
    assert!(matches!(
        bounded
            .page(
                &board,
                request(&a, &ac, None, 3),
                &alice.verification(),
                &clean
            )
            .await,
        Err(LookupError::Invalid)
    ));
    assert!(matches!(
        bounded
            .ciphertext(
                &board,
                request(&a, &ac, None, 1),
                ("bob", 1),
                &alice.verification(),
                &clean
            )
            .await,
        Err(LookupError::Invalid)
    ));
    // A real signed block replaces the whole committed publication. Old
    // observations cannot survive the atomic read boundary.
    let observed_a = board
        .requester(&a, &ac, &alice.verification(), &clean)
        .await
        .unwrap();
    let observed_b = board
        .candidate(&a, &ac, "bob", &alice.verification(), &clean)
        .await
        .unwrap();
    let blocked = Fixture::with_rules(
        "bob",
        2,
        now,
        vec![cgrd::Rule::Block {
            member: "alice".into(),
        }],
    )
    .await;
    let replacement = board
        .replacement(&b, &bc, &blocked.publication, &bob.verification(), &clean)
        .await
        .unwrap();
    board
        .replace(&b, &bc, bl.revision, replacement)
        .await
        .unwrap();
    assert!(matches!(
        board
            .confirm(&[&observed_a, &observed_b], &alice.verification(), &clean)
            .await,
        Err(cswb::Error::Storage(cmmr::Error::Conflict))
    ));
    assert!(matches!(
        lookup
            .ciphertext(
                &board,
                request(&a, &ac, None, 1),
                ("bob", 2),
                &alice.verification(),
                &clean
            )
            .await,
        Err(LookupError::ResetRequired)
    ));
    let removed = lookup
        .watch(
            &board,
            WatchRequest {
                session: &a,
                current: &ac,
                cursor: &second.watch,
            },
            &alice.verification(),
            &clean,
        )
        .await
        .unwrap();
    assert_eq!(removed.removed, ["bob"]);
    assert!(removed.upserts.is_empty());
    let page = lookup
        .page(
            &board,
            request(&a, &ac, None, 3),
            &alice.verification(),
            &clean,
        )
        .await
        .unwrap();
    assert_eq!(
        page.entries
            .iter()
            .map(|e| e.member.as_str())
            .collect::<Vec<_>>(),
        vec!["carol"]
    );
    let cc = current(&board, &c, &mut carol, 3).await;
    let updated_carol = Fixture::new("carol", 2, now).await;
    let replacement = board
        .replacement(
            &c,
            &cc,
            &updated_carol.publication,
            &carol.verification(),
            &clean,
        )
        .await
        .unwrap();
    board
        .replace(&c, &cc, cl.revision, replacement)
        .await
        .unwrap();
    let updated = lookup
        .watch(
            &board,
            WatchRequest {
                session: &a,
                current: &ac,
                cursor: &page.watch,
            },
            &alice.verification(),
            &clean,
        )
        .await
        .unwrap();
    assert!(updated.removed.is_empty());
    assert_eq!(updated.upserts.len(), 1);
    assert_eq!(updated.upserts[0].member, "carol");
    assert_eq!(updated.upserts[0].revision, 2);
    assert_eq!(
        updated.upserts[0].publication,
        updated_carol.publication.signed
    );
    board.heartbeat(&a, &ac, al.revision).await.unwrap();
    assert!(matches!(
        lookup
            .watch(
                &board,
                WatchRequest {
                    session: &a,
                    current: &ac,
                    cursor: &updated.watch
                },
                &alice.verification(),
                &clean
            )
            .await,
        Err(LookupError::ResetRequired)
    ));
    assert!(matches!(
        lookup
            .page(
                &board,
                request(&a, &ac, Some(&next), 1),
                &alice.verification(),
                &clean
            )
            .await,
        Err(LookupError::Cursor(CursorError::ResetRequired))
    ));
    let before = board
        .candidate(&a, &ac, "carol", &alice.verification(), &clean)
        .await
        .unwrap();
    board.depart(&c).await.unwrap();
    assert!(matches!(
        board
            .confirm(&[&before], &alice.verification(), &clean)
            .await,
        Err(cswb::Error::Storage(cmmr::Error::Conflict))
    ));
    alice.revoke("bob");
    let page = lookup
        .page(
            &board,
            request(&a, &ac, None, 3),
            &alice.verification(),
            &clean,
        )
        .await
        .unwrap();
    assert!(page.entries.is_empty());
    assert!(store.get("swb_bob").await.unwrap().is_none());
    board.depart(&a).await.unwrap();
    assert!(matches!(
        lookup
            .page(
                &board,
                request(&a, &ac, None, 3),
                &alice.verification(),
                &clean
            )
            .await,
        Err(LookupError::Presence(cswb::Error::Absent))
    ));
}

#[tokio::test]
async fn committed_memory_pages_and_immediate_invalidation() {
    let now = 2_000_000_000;
    let clock = Time(Arc::new(AtomicU64::new(now * 1000)));
    let store = Arc::new(
        cmmr::Memory::new(
            cmmr::Scope::new("garden", "lookup").unwrap(),
            limits(),
            clock.clone(),
        )
        .unwrap(),
    );
    round_trip(store, clock, now).await;
}

#[derive(Clone)]
struct Wall;
impl Clock for Wall {
    fn now(&self) -> Result<u64, cmmr::Error> {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|t| t.as_millis() as u64)
            .map_err(|_| cmmr::Error::Unavailable)
    }
}
#[tokio::test]
async fn committed_valkey_pages_and_immediate_invalidation() {
    if std::env::var_os("VALKEY_URL").is_none() {
        eprintln!("skipped: VALKEY_URL is required (disposable Valkey)");
        return;
    }
    let now = Wall.now().unwrap() / 1000;
    let connection =
        redis::Client::open(std::env::var("VALKEY_URL").expect("disposable Valkey required"))
            .unwrap()
            .get_multiplexed_async_connection()
            .await
            .unwrap();
    let network =
        Arc::new(cvlk::RedisNetwork::new(connection, std::time::Duration::from_secs(5)).unwrap());
    let generation = data_encoding::HEXLOWER.encode(&Random.next().unwrap());
    let store = Arc::new(
        cvlk::Valkey::open(
            network,
            cmmr::Scope::new("garden", generation).unwrap(),
            limits(),
            Wall,
        )
        .await
        .unwrap(),
    );
    round_trip(store, Wall, now).await;
}

#[path = "live/associated.rs"]
mod associated;
