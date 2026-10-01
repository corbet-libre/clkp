use super::*;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
struct Time(AtomicU64);
impl cmmr::Clock for Time {
    fn now(&self) -> Result<u64, cmmr::Error> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}
struct Sequence(AtomicU64);
impl cswb::Tokens for Sequence {
    fn next(&self) -> Result<[u8; 16], cswb::Error> {
        Ok((self.0.fetch_add(1, Ordering::SeqCst) as u128).to_be_bytes())
    }
}
fn context() -> CursorContext {
    CursorContext {
        community: "community".into(),
        requester: "alice".into(),
        generation: "generation".into(),
        epoch: 1,
        schema: 1,
        revision: Revision([5; 16]),
        query: [7; 32],
    }
}
type Fixture = Cursors<Arc<cmmr::Memory<Arc<Time>>>, Sequence>;
fn setup() -> (Fixture, Arc<Time>) {
    let time = Arc::new(Time(AtomicU64::new(100)));
    let store = Arc::new(
        cmmr::Memory::new(
            cmmr::Scope::new("community", "boot").unwrap(),
            cmmr::Limits {
                records: 4,
                value_bytes: 4096,
                batch: 2,
                indexes_per_record: 0,
                page: 8,
                ttl_ms: 1000,
            },
            time.clone(),
        )
        .unwrap(),
    );
    (Cursors::new(store, Sequence(AtomicU64::new(1))), time)
}
#[tokio::test]
async fn cursors_are_opaque_bound_expiring_and_deleted_with_attendance() {
    let (cursors, time) = setup();
    let token = cursors
        .issue(context(), "position".into(), Deadline::new(200).unwrap())
        .await
        .unwrap();
    assert_eq!(serde_json::to_vec(&token).unwrap().len(), 33);
    let value = cursors.resume(&token, &context()).await.unwrap();
    assert_eq!(value.after(), "position");
    assert_eq!(value.deadline().unix_ms(), 200);
    for mode in 0..7 {
        let mut foreign = context();
        match mode {
            0 => foreign.community = "foreign".into(),
            1 => foreign.requester = "bob".into(),
            2 => foreign.generation = "new".into(),
            3 => foreign.epoch = 2,
            4 => foreign.query = [8; 32],
            5 => foreign.schema = 2,
            _ => foreign.revision = Revision([6; 16]),
        }
        assert!(matches!(
            cursors.resume(&token, &foreign).await,
            Err(CursorError::ResetRequired)
        ));
    }
    time.0.store(200, Ordering::SeqCst);
    assert!(matches!(
        cursors.resume(&token, &context()).await,
        Err(CursorError::ResetRequired)
    ));
    let token = cursors
        .issue(context(), "next".into(), Deadline::new(300).unwrap())
        .await
        .unwrap();
    cursors.store.delete_generation("generation").await.unwrap();
    assert!(matches!(
        cursors.resume(&token, &context()).await,
        Err(CursorError::ResetRequired)
    ));
}
#[tokio::test]
async fn invalid_and_exhausted_continuations_refuse_without_eviction() {
    let (mut cursors, _) = setup();
    for mode in 0..7 {
        let mut bad = context();
        let mut after = String::new();
        match mode {
            0 => bad.community = "!".into(),
            1 => bad.requester = "!".into(),
            2 => bad.generation = "!".into(),
            3 => bad.epoch = 0,
            4 => after = "x".repeat(146),
            5 => bad.schema = 0,
            _ => bad.revision = Revision([0; 16]),
        }
        assert!(
            cursors
                .issue(bad, after, Deadline::new(200).unwrap())
                .await
                .is_err()
        );
    }
    cursors.tokens = Sequence(AtomicU64::new(0));
    assert!(matches!(
        cursors
            .issue(context(), String::new(), Deadline::new(200).unwrap())
            .await,
        Err(CursorError::Entropy)
    ));
    for _ in 0..4 {
        cursors
            .issue(context(), String::new(), Deadline::new(200).unwrap())
            .await
            .unwrap();
    }
    assert!(matches!(
        cursors
            .issue(context(), String::new(), Deadline::new(200).unwrap())
            .await,
        Err(CursorError::Storage(cmmr::Error::Capacity))
    ));
    let token = Cursor(1u128.to_be_bytes());
    let mut row = cursors.store.get(&key(&token)).await.unwrap().unwrap();
    let revision = row.revision;
    row.value = vec![0];
    row.revision = Revision([8; 16]);
    cursors
        .store
        .compare_exchange(&[Write {
            expected: Some(revision),
            record: row,
        }])
        .await
        .unwrap();
    assert!(matches!(
        cursors.resume(&token, &context()).await,
        Err(CursorError::ResetRequired)
    ));
}
