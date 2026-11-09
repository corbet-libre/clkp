//! Real signed auxiliary-publication boundary tests. These are not G2 evidence.
use super::*;
use csgn::{KeyRing, Kind, SecretKey, Signer, Verified};
use std::collections::BTreeMap;

struct SignedEvidence {
    signed: Vec<u8>,
    verified: Verified,
    row_until: u64,
}
struct SignedOwner {
    ring: KeyRing,
    publications: BTreeMap<String, Vec<u8>>,
    clock: Time,
    floor: u64,
}
impl SignedOwner {
    fn now(&mut self) -> Result<u64, LookupError> {
        let now = self.clock.now().map_err(|_| LookupError::Associated)?;
        if now < self.floor {
            return Err(LookupError::Associated);
        }
        self.floor = now;
        Ok(now / 1000)
    }
}
impl AssociatedEvidence for SignedOwner {
    type Evidence = SignedEvidence;
    fn verify(
        &mut self,
        row: &cswb::VerifiedPresence,
    ) -> Result<Option<SignedEvidence>, LookupError> {
        let now = self.now()?;
        let Some(signed) = self.publications.get(&row.binding().member) else {
            return Ok(None);
        };
        let Ok(verified) = self.ring.verify(signed, Kind::SettingsSnapshot, now) else {
            return Ok(None);
        };
        // This private fixture publication identifies the exact real committed
        // scope/revision. It claims no accounting or complete-admission verdict.
        if verified.payload() != serde_json::to_vec(&(row.binding(), row.revision())).unwrap() {
            return Ok(None);
        }
        Ok(Some(SignedEvidence {
            signed: signed.clone(),
            verified,
            row_until: row.deadline(),
        }))
    }
    fn current(&mut self, evidence: &SignedEvidence) -> Result<(), LookupError> {
        let now = self.now()?;
        self.ring
            .verify(&evidence.signed, Kind::SettingsSnapshot, now)
            .map_err(|_| LookupError::Associated)?;
        if self.floor >= evidence.row_until {
            return Err(LookupError::Associated);
        }
        Ok(())
    }
    fn valid_until(&self, evidence: &SignedEvidence) -> u64 {
        evidence.verified.valid_until() * 1000
    }
}
fn cursor_record(cursor: &Cursor) -> String {
    format!("lkp_{}", data_encoding::HEXLOWER.encode(&cursor.0))
}
fn setup<S: Store + Clone>(
    store: S,
    clock: Time,
) -> (Switchboard<S, Time, Random>, Lookup<S, Random>) {
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
        store,
        Random,
        LookupLimits {
            candidates: 5,
            publication_bytes: cpfl::MAX_PROFILE_BYTES * 5,
        },
    )
    .unwrap();
    (board, lookup)
}
async fn owner<S: Store>(
    board: &Switchboard<S, Time, Random>,
    session: &Session,
    current: &Current,
    alice: &mut Fixture,
    members: &[&str],
    clock: Time,
    ttl: u64,
) -> SignedOwner {
    let now = clock.now().unwrap() / 1000;
    let mut signer = Signer::new(
        "garden",
        SecretKey::from_seed(&mut [42; 32]),
        now - 10,
        3600,
    )
    .unwrap();
    let mut publications = BTreeMap::new();
    let mut chronological = members.to_vec();
    chronological.sort_by_key(|member| usize::from(*member != "expired"));
    for member in chronological {
        let row = board
            .candidate(session, current, member, &alice.verification(), &clean)
            .await
            .unwrap();
        let bytes = serde_json::to_vec(&(row.binding(), row.revision())).unwrap();
        let (issued, until) = match member {
            "expired" => (now - 3, now - 1),
            "bob" => (now, now + ttl - 2),
            _ => (now, now + ttl),
        };
        let mut signed = signer
            .sign(Kind::SettingsSnapshot, &bytes, issued, until)
            .unwrap();
        if member == "bad" {
            let last = signed.len() - 1;
            signed[last] ^= 1;
        }
        publications.insert(member.into(), signed);
    }
    SignedOwner {
        ring: signer.key_ring().clone(),
        publications,
        floor: clock.now().unwrap(),
        clock,
    }
}

#[tokio::test]
async fn signed_evidence_omission_cursor_domain_and_observation_deadlines() {
    let now = 2_000_000_000;
    let clock = Time(Arc::new(AtomicU64::new(now * 1000)));
    let store = Arc::new(
        cmmr::Memory::new(
            cmmr::Scope::new("garden", "associated").unwrap(),
            limits(),
            clock.clone(),
        )
        .unwrap(),
    );
    let (board, lookup) = setup(store.clone(), clock.clone());
    let mut fixtures = Vec::new();
    let mut sessions = Vec::new();
    for member in ["alice", "bad", "bob", "expired", "missing"] {
        let mut fixture = Fixture::new(member, 1, now).await;
        sessions.push(enter(&board, &mut fixture).await.0);
        fixtures.push(fixture);
    }
    let a = &sessions[0];
    let ac = current(&board, a, &mut fixtures[0], 1).await;
    let mut evidence = owner(
        &board,
        a,
        &ac,
        &mut fixtures[0],
        &["alice", "bad", "bob", "expired"],
        clock.clone(),
        5,
    )
    .await;
    let legacy = lookup
        .page(
            &board,
            request(a, &ac, None, 1),
            &fixtures[0].verification(),
            &clean,
        )
        .await
        .unwrap();
    assert!(matches!(
        lookup
            .page_with(
                &board,
                request(a, &ac, legacy.next.as_ref(), 1),
                &fixtures[0].verification(),
                &clean,
                &mut evidence
            )
            .await,
        Err(LookupError::Cursor(CursorError::ResetRequired))
    ));
    assert!(matches!(
        lookup
            .watch_with(
                &board,
                WatchRequest {
                    session: a,
                    current: &ac,
                    cursor: &legacy.watch
                },
                &fixtures[0].verification(),
                &clean,
                &mut evidence
            )
            .await,
        Err(LookupError::ResetRequired)
    ));
    let checked = lookup
        .page_with(
            &board,
            request(a, &ac, None, 5),
            &fixtures[0].verification(),
            &clean,
            &mut evidence,
        )
        .await
        .unwrap();
    assert_eq!(
        checked
            .entries
            .iter()
            .map(|entry| entry.member.as_str())
            .collect::<Vec<_>>(),
        ["bob"]
    );
    let record = store
        .get(&cursor_record(&checked.watch))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.deadline.unix_ms(), (now + 3) * 1000);
    let saved: serde_json::Value = serde_json::from_slice(&record.value).unwrap();
    assert_eq!(saved["watch"]["seen"].as_array().unwrap().len(), 1);
    assert_eq!(saved["watch"]["seen"][0]["member"], "bob");
    assert!(matches!(
        lookup
            .watch(
                &board,
                WatchRequest {
                    session: a,
                    current: &ac,
                    cursor: &checked.watch
                },
                &fixtures[0].verification(),
                &clean
            )
            .await,
        Err(LookupError::ResetRequired)
    ));
    for index in [1, 3, 4] {
        board.depart(&sessions[index]).await.unwrap();
    }
    let delta = lookup
        .watch_with(
            &board,
            WatchRequest {
                session: a,
                current: &ac,
                cursor: &checked.watch,
            },
            &fixtures[0].verification(),
            &clean,
            &mut evidence,
        )
        .await
        .unwrap();
    assert!(delta.removed.is_empty());
    assert!(delta.upserts.is_empty());
    board.depart(&sessions[2]).await.unwrap();
    let delta = lookup
        .watch_with(
            &board,
            WatchRequest {
                session: a,
                current: &ac,
                cursor: &delta.watch,
            },
            &fixtures[0].verification(),
            &clean,
            &mut evidence,
        )
        .await
        .unwrap();
    assert_eq!(delta.removed, ["bob"]);
    evidence.publications.remove("alice");
    assert!(matches!(
        lookup
            .page_with(
                &board,
                request(a, &ac, None, 5),
                &fixtures[0].verification(),
                &clean,
                &mut evidence
            )
            .await,
        Err(LookupError::Associated)
    ));
    store.close();
}

#[path = "associated_awaits.rs"]
mod awaits;
