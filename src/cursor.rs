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
}

/// Only an internal index position, never permission to reveal a candidate.
pub struct Continuation {
    after: String,
    deadline: Deadline,
}
impl Continuation {
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
        let value =
            serde_json::to_vec(&Saved { context, after }).map_err(|_| CursorError::Invalid)?;
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
        if &saved.context != expected {
            return Err(CursorError::ResetRequired);
        }
        Ok(Continuation {
            after: saved.after,
            deadline: record.deadline,
        })
    }
}

fn key(cursor: &Cursor) -> String {
    let token: String = cursor.0.iter().map(|b| format!("{b:02x}")).collect();
    format!("lkp_{token}")
}

#[cfg(test)]
#[path = "cursor_tests.rs"]
mod tests;
