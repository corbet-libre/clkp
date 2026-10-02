use cmmr::{Deadline, Record, Revision, Store, Write};
use serde::{Deserialize, Serialize};

/// Service-derived context. This is cursor binding, not admission evidence.
/// The caller must first obtain current Switchboard device authorization.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CursorContext {
    pub community: String,
    pub requester: String,
    pub generation: String,
    pub epoch: u64,
    pub schema: u32,
    pub revision: Revision,
    pub query: [u8; 32],
}

/// Random lookup token. It carries no serialized profile, query or identifier.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cursor(pub [u8; 16]);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CursorError {
    Invalid,
    ResetRequired,
    Storage(cmmr::Error),
    Entropy,
}
impl From<cmmr::Error> for CursorError {
    fn from(value: cmmr::Error) -> Self {
        Self::Storage(value)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Saved {
    context: CursorContext,
    after: String,
    #[serde(default)]
    storage: Option<cmmr::Cursor>,
    #[serde(default)]
    watch: Option<Window>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Window {
    pub start: Option<cmmr::Cursor>,
    pub limit: usize,
    pub seen: Vec<Seen>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Seen {
    pub member: String,
    pub revision: u64,
    pub digest: [u8; 32],
}

/// Only an internal index position, never permission to reveal a candidate.
pub struct Continuation {
    after: String,
    deadline: Deadline,
    storage: Option<cmmr::Cursor>,
}
impl Continuation {
    pub fn storage(&self) -> Option<&cmmr::Cursor> {
        self.storage.as_ref()
    }
    pub fn after(&self) -> &str {
        &self.after
    }
    pub fn deadline(&self) -> Deadline {
        self.deadline
    }
}

pub struct Cursors<S, R> {
    store: S,
    tokens: R,
}
impl<S: Store, R: cswb::Tokens> Cursors<S, R> {
    pub fn new(store: S, tokens: R) -> Self {
        Self { store, tokens }
    }

    pub async fn issue(
        &self,
        context: CursorContext,
        after: String,
        deadline: Deadline,
    ) -> Result<Cursor, CursorError> {
        self.save(context, after, None, None, deadline).await
    }

    /// Retain the storage owner's exact scoped continuation behind the opaque
    /// public token. The outer deadline never outlives requester authority.
    pub async fn issue_page(
        &self,
        context: CursorContext,
        storage: cmmr::Cursor,
        deadline: Deadline,
    ) -> Result<Cursor, CursorError> {
        let deadline = Deadline::new(deadline.unix_ms().min(storage.deadline().unix_ms()))?;
        self.save(
            context,
            storage.after().into(),
            Some(storage),
            None,
            deadline,
        )
        .await
    }

    async fn save(
        &self,
        context: CursorContext,
        after: String,
        storage: Option<cmmr::Cursor>,
        watch: Option<Window>,
        deadline: Deadline,
    ) -> Result<Cursor, CursorError> {
        cmmr::validate_name(&context.community)?;
        cmmr::validate_name(&context.requester)?;
        cmmr::validate_name(&context.generation)?;
        if context.epoch == 0
            || context.schema == 0
            || context.revision.0 == [0; 16]
            || after.len() > 145
        {
            return Err(CursorError::Invalid);
        }
        let token = self.tokens.next().map_err(|_| CursorError::Entropy)?;
        if token == [0; 16] {
            return Err(CursorError::Entropy);
        }
        let cursor = Cursor(token);
        let generation = context.generation.clone();
        let value = serde_json::to_vec(&Saved {
            context,
            after,
            storage,
            watch,
        })
        .map_err(|_| CursorError::Invalid)?;
        self.store
            .compare_exchange(&[Write {
                expected: None,
                record: Record {
                    key: key(&cursor),
                    generation,
                    revision: Revision(token),
                    deadline,
                    value,
                    indexes: vec![],
                },
            }])
            .await?;
        Ok(cursor)
    }

    pub(crate) async fn issue_watch(
        &self,
        context: CursorContext,
        window: Window,
        deadline: Deadline,
    ) -> Result<Cursor, CursorError> {
        let until = window.start.as_ref().map_or(deadline.unix_ms(), |start| {
            start.deadline().unix_ms().min(deadline.unix_ms())
        });
        self.save(
            context,
            String::new(),
            None,
            Some(window),
            Deadline::new(until)?,
        )
        .await
    }

    /// A bounded observation is not authority. Lookup must verify this returned
    /// context against the fresh requester before using any member identifier.
    pub(crate) async fn watch(
        &self,
        cursor: &Cursor,
    ) -> Result<(CursorContext, Window, Deadline), CursorError> {
        let record = self
            .store
            .get(&key(cursor))
            .await?
            .ok_or(CursorError::ResetRequired)?;
        let saved: Saved =
            serde_json::from_slice(&record.value).map_err(|_| CursorError::ResetRequired)?;
        if saved.storage.is_some() || !saved.after.is_empty() {
            return Err(CursorError::ResetRequired);
        }
        let window = saved.watch.ok_or(CursorError::ResetRequired)?;
        Ok((saved.context, window, record.deadline))
    }

    /// Resuming never refreshes expiry. Departure deletes the same generation
    /// as attendance; stale scope/query/epoch/generation requires a fresh page.
    pub async fn resume(
        &self,
        cursor: &Cursor,
        expected: &CursorContext,
    ) -> Result<Continuation, CursorError> {
        let record = self
            .store
            .get(&key(cursor))
            .await?
            .ok_or(CursorError::ResetRequired)?;
        let saved: Saved =
            serde_json::from_slice(&record.value).map_err(|_| CursorError::ResetRequired)?;
        if &saved.context != expected || saved.watch.is_some() {
            return Err(CursorError::ResetRequired);
        }
        Ok(Continuation {
            after: saved.after,
            deadline: record.deadline,
            storage: saved.storage,
        })
    }
}

fn key(cursor: &Cursor) -> String {
    let token = data_encoding::HEXLOWER.encode(&cursor.0);
    format!("lkp_{token}")
}

#[cfg(test)]
#[path = "cursor_tests.rs"]
mod tests;
