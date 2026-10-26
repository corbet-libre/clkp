//! Expiry after each real store operation, with no fabricated owner verdict.
use super::*;

struct AwaitClock {
    count: AtomicU64,
    trigger: AtomicU64,
    clock: Time,
    advance_to: u64,
}
impl AwaitClock {
    fn completed(&self) {
        let count = self.count.fetch_add(1, Ordering::SeqCst) + 1;
        if count == self.trigger.load(Ordering::SeqCst) {
            self.clock.0.store(self.advance_to, Ordering::SeqCst);
        }
    }
}
#[derive(Clone)]
struct Observed<S> {
    real: S,
    clock: Arc<AwaitClock>,
}
impl<S: Store> Store for Observed<S> {
    fn state(&self) -> cmmr::State {
        self.real.state()
    }
    async fn get(&self, key: &str) -> Result<Option<cmmr::Record>, cmmr::Error> {
        let result = self.real.get(key).await;
        self.clock.completed();
        result
    }
    async fn check_current(&self, checks: &[cmmr::Check]) -> Result<(), cmmr::Error> {
        let result = self.real.check_current(checks).await;
        self.clock.completed();
        result
    }
    async fn compare_exchange(&self, writes: &[cmmr::Write]) -> Result<(), cmmr::Error> {
        let result = self.real.compare_exchange(writes).await;
        self.clock.completed();
        result
    }
    async fn delete_generation(&self, generation: &str) -> Result<usize, cmmr::Error> {
        let result = self.real.delete_generation(generation).await;
        self.clock.completed();
        result
    }
    async fn page(
        &self,
        index: &str,
        cursor: Option<&cmmr::Cursor>,
        limit: usize,
    ) -> Result<cmmr::Page, cmmr::Error> {
        let result = self.real.page(index, cursor, limit).await;
        self.clock.completed();
        result
    }
    async fn maintain(&self) -> Result<usize, cmmr::Error> {
        let result = self.real.maintain().await;
        self.clock.completed();
        result
    }
    fn close(&self) {
        self.real.close();
    }
}

async fn at_await(operation: u8, trigger: u64, row_expiry: bool) -> u64 {
    let now = 2_000_000_000;
    let real_clock = Time(Arc::new(AtomicU64::new(now * 1000)));
    let owner_clock = Time(Arc::new(AtomicU64::new(now * 1000)));
    let observed = Arc::new(AwaitClock {
        count: AtomicU64::new(0),
        trigger: AtomicU64::new(0),
        clock: owner_clock.clone(),
        advance_to: (now + if row_expiry { 61 } else { 3 }) * 1000,
    });
    let real = Arc::new(
        cmmr::Memory::new(
            cmmr::Scope::new("garden", "awaits").unwrap(),
            limits(),
            real_clock.clone(),
        )
        .unwrap(),
    );
    let store = Observed {
        real,
        clock: observed.clone(),
    };
    let (board, lookup) = setup(store.clone(), real_clock);
    let mut alice = Fixture::new("alice", 1, now).await;
    let mut bob = Fixture::new("bob", 1, now).await;
    let (session, _) = enter(&board, &mut alice).await;
    enter(&board, &mut bob).await;
    let current = current(&board, &session, &mut alice, 1).await;
    let mut evidence = owner(
        &board,
        &session,
        &current,
        &mut alice,
        &["alice", "bob"],
        owner_clock,
        if row_expiry { 120 } else { 3 },
    )
    .await;
    let watch = lookup
        .page_with(
            &board,
            request(&session, &current, None, 2),
            &alice.verification(),
            &clean,
            &mut evidence,
        )
        .await
        .unwrap()
        .watch;
    observed.count.store(0, Ordering::SeqCst);
    observed.trigger.store(trigger, Ordering::SeqCst);
    // Each case owns a fresh actual store and signer/clock. For row expiry the
    // auxiliary signatures stay valid beyond the exact initial liveness bound.
    let result = match operation {
        0 => lookup
            .page_with(
                &board,
                request(&session, &current, None, 2),
                &alice.verification(),
                &clean,
                &mut evidence,
            )
            .await
            .map(|_| ()),
        1 => lookup
            .watch_with(
                &board,
                WatchRequest {
                    session: &session,
                    current: &current,
                    cursor: &watch,
                },
                &alice.verification(),
                &clean,
                &mut evidence,
            )
            .await
            .map(|_| ()),
        2 => lookup
            .ciphertext_with(
                &board,
                CiphertextRequest {
                    request: request(&session, &current, None, 2),
                    member: "bob",
                    revision: 1,
                },
                &alice.verification(),
                &clean,
                &mut evidence,
            )
            .await
            .map(|_| ()),
        _ => unreachable!(),
    };
    if trigger == 0 {
        assert!(result.is_ok());
    } else {
        assert!(matches!(result, Err(LookupError::Associated)));
    }
    let count = observed.count.load(Ordering::SeqCst);
    assert!(trigger == 0 || count >= trigger);
    store.close();
    count
}

#[tokio::test]
async fn every_real_storage_await_rechecks_signed_evidence_and_exact_row_expiry() {
    for operation in 0..3 {
        for row_expiry in [false, true] {
            let operations = at_await(operation, 0, row_expiry).await;
            assert!(operations > 0);
            for trigger in 1..=operations {
                at_await(operation, trigger, row_expiry).await;
            }
        }
    }
}
