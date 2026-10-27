mod associated;
mod operations;
pub use associated::AssociatedEvidence;
use associated::Evidence;
pub use operations::CiphertextRequest;

use crate::cursor::{Seen, Window};
use crate::{Cursor, CursorContext, CursorError, Cursors};
use cmmr::{Clock, Deadline, Revision, Store};
use cswb::{Current, Session, Switchboard, Tokens, Verification, VerifiedPresence};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy)]
pub struct LookupLimits {
    /// Maximum rows examined per request, including nonmatches.
    pub candidates: usize,
    /// Maximum total original publication bytes disclosed in one response.
    pub publication_bytes: usize,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LookupError {
    Invalid,
    ResetRequired,
    Presence(cswb::Error),
    Cursor(CursorError),
    Associated,
}
impl From<cswb::Error> for LookupError {
    fn from(error: cswb::Error) -> Self {
        Self::Presence(error)
    }
}
impl From<CursorError> for LookupError {
    fn from(error: CursorError) -> Self {
        Self::Cursor(error)
    }
}

pub struct PageRequest<'a> {
    pub session: &'a Session,
    pub current: &'a Current,
    pub cursor: Option<&'a Cursor>,
    pub limit: usize,
}
/// Original signed bytes after current two-way authorization. A receiving
/// device still rechecks these with Search before display or key exchange.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Match {
    pub member: String,
    pub revision: u64,
    pub publication: Vec<u8>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Matches {
    pub requester_revision: Revision,
    pub entries: Vec<Match>,
    pub next: Option<Cursor>,
    /// Opaque polling cursor for this bounded candidate window, not the roster.
    pub watch: Cursor,
}

pub struct WatchRequest<'a> {
    pub session: &'a Session,
    pub current: &'a Current,
    pub cursor: &'a Cursor,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Delta {
    pub requester_revision: Revision,
    pub upserts: Vec<Match>,
    pub removed: Vec<String>,
    pub watch: Cursor,
    pub next: Option<Cursor>,
}

/// No second profile table or retained verdict: all rows come from current
/// committed Switchboard state, and only opaque cursors live in this child.
pub struct Lookup<S, R> {
    cursors: Cursors<S, R>,
    limits: LookupLimits,
}
impl<S: Store, R: Tokens> Lookup<S, R> {
    pub fn new(store: S, tokens: R, limits: LookupLimits) -> Result<Self, LookupError> {
        // One additional record in the atomic read batch is the requester.
        if limits.candidates == 0 || limits.candidates > 255 || limits.publication_bytes == 0 {
            return Err(LookupError::Invalid);
        }
        Ok(Self {
            cursors: Cursors::new(store, tokens),
            limits,
        })
    }

    async fn page_inner<B: Store, C: Clock, T: Tokens, E: AssociatedEvidence>(
        &self,
        board: &Switchboard<B, C, T>,
        request: PageRequest<'_>,
        verification: &Verification<'_>,
        contact: &impl Fn(&str) -> cshm::ContactCheck,
        evidence: &mut Evidence<'_, E>,
    ) -> Result<Matches, LookupError> {
        if request.limit == 0 || request.limit > self.limits.candidates {
            return Err(LookupError::Invalid);
        }
        let requester = board
            .requester(request.session, request.current, verification, contact)
            .await?;
        evidence.require(&requester)?;
        let context = context(
            &requester,
            request.limit,
            verification.charter.revision(),
            evidence.is_checked(),
        );
        let continuation = match request.cursor {
            Some(cursor) => Some(self.cursors.resume(cursor, &context).await?),
            None => None,
        };
        evidence.current()?;
        let internal = match &continuation {
            Some(saved) => Some(saved.storage().ok_or(LookupError::ResetRequired)?),
            None => None,
        };
        self.window(
            board,
            request,
            (requester, internal),
            verification,
            contact,
            evidence,
        )
        .await
    }

    async fn window<B: Store, C: Clock, T: Tokens, E: AssociatedEvidence>(
        &self,
        board: &Switchboard<B, C, T>,
        request: PageRequest<'_>,
        start: (VerifiedPresence, Option<&cmmr::Cursor>),
        verification: &Verification<'_>,
        contact: &impl Fn(&str) -> cshm::ContactCheck,
        evidence: &mut Evidence<'_, E>,
    ) -> Result<Matches, LookupError> {
        let (requester, internal) = start;
        let context = context(
            &requester,
            request.limit,
            verification.charter.revision(),
            evidence.is_checked(),
        );
        let page = board
            .candidates(
                cswb::Scan {
                    session: request.session,
                    current: request.current,
                    cursor: internal,
                    limit: request.limit,
                },
                verification,
                contact,
            )
            .await?;
        evidence.current()?;
        // One member counts once no matter how many device rows it holds:
        // keep the freshest verified profile revision per member before any
        // reciprocal check, byte budget or atomic cut.
        let mut freshest: Vec<&VerifiedPresence> = Vec::new();
        for row in &page.candidates {
            match freshest
                .iter_mut()
                .find(|slot| slot.binding().member == row.binding().member)
            {
                Some(slot)
                    if row.profile().transcript().revision
                        > slot.profile().transcript().revision =>
                {
                    *slot = row;
                }
                Some(_) => {}
                None => freshest.push(row),
            }
        }
        let mut selected = Vec::new();
        let mut remaining = self.limits.publication_bytes;
        for row in freshest {
            if cgrd::matches(
                requester.profile().participant(),
                row.profile().participant(),
            )
            .is_match()
            {
                if !evidence.include(row)? {
                    continue;
                }
                remaining = remaining
                    .checked_sub(row.publication().signed.len())
                    .ok_or(LookupError::Invalid)?;
                selected.push(row);
            }
        }
        // Guard rejects self-pairs. All selected records and the requester must
        // exist together at one atomic cut before any result can be returned.
        let mut checks = vec![&requester];
        checks.extend(selected.iter().copied());
        board.confirm(&checks, verification, contact).await?;
        evidence.current()?;
        let deadline =
            Deadline::new(evidence.deadline(requester.deadline())).map_err(cswb::Error::from)?;
        let next = match page.next {
            Some(cursor) => Some(
                self.cursors
                    .issue_page(context.clone(), cursor, deadline)
                    .await?,
            ),
            None => None,
        };
        evidence.current()?;
        let watch = self
            .cursors
            .issue_watch(
                context,
                Window {
                    start: internal.cloned(),
                    limit: request.limit,
                    seen: selected
                        .iter()
                        .map(|row| Seen {
                            member: row.binding().member.clone(),
                            revision: row.profile().transcript().revision,
                            digest: Sha256::digest(&row.publication().signed).into(),
                        })
                        .collect(),
                },
                deadline,
            )
            .await?;
        evidence.current()?;
        board.confirm(&checks, verification, contact).await?;
        evidence.current()?;
        Ok(Matches {
            requester_revision: requester.revision(),
            entries: selected
                .into_iter()
                .map(|row| Match {
                    member: row.binding().member.clone(),
                    revision: row.profile().transcript().revision,
                    publication: row.publication().signed.clone(),
                })
                .collect(),
            next,
            watch,
        })
    }

    /// Poll one previous bounded window. No publications or verdicts are kept
    /// in its cursor: only observed IDs/revisions/digests until the ORIGINAL
    /// requester deadline. Re-evaluate the current candidate window in full.
    async fn watch_inner<B: Store, C: Clock, T: Tokens, E: AssociatedEvidence>(
        &self,
        board: &Switchboard<B, C, T>,
        request: WatchRequest<'_>,
        verification: &Verification<'_>,
        contact: &impl Fn(&str) -> cshm::ContactCheck,
        evidence: &mut Evidence<'_, E>,
    ) -> Result<Delta, LookupError> {
        let requester = board
            .requester(request.session, request.current, verification, contact)
            .await?;
        evidence.require(&requester)?;
        let (saved, window, _) = self.cursors.watch(request.cursor).await?;
        evidence.current()?;
        if window.limit == 0
            || window.limit > self.limits.candidates
            || window.seen.len() > window.limit
            || saved
                != context(
                    &requester,
                    window.limit,
                    verification.charter.revision(),
                    evidence.is_checked(),
                )
        {
            return Err(LookupError::ResetRequired);
        }
        let mut unique = std::collections::BTreeSet::new();
        for seen in &window.seen {
            if seen.revision == 0
                || cmmr::validate_name(&seen.member).is_err()
                || !unique.insert(&seen.member)
            {
                return Err(LookupError::ResetRequired);
            }
        }
        let page = self
            .window(
                board,
                PageRequest {
                    session: request.session,
                    current: request.current,
                    cursor: None,
                    limit: window.limit,
                },
                (requester, window.start.as_ref()),
                verification,
                contact,
                evidence,
            )
            .await?;
        evidence.current()?;
        let removed = window
            .seen
            .iter()
            .filter(|old| !page.entries.iter().any(|new| new.member == old.member))
            .map(|old| old.member.clone())
            .collect();
        let upserts = page
            .entries
            .into_iter()
            .filter(|new| {
                !window.seen.iter().any(|old| {
                    old.member == new.member
                        && old.revision == new.revision
                        && old.digest == <[u8; 32]>::from(Sha256::digest(&new.publication))
                })
            })
            .collect();
        Ok(Delta {
            requester_revision: page.requester_revision,
            upserts,
            removed,
            watch: page.watch,
            next: page.next,
        })
    }

    /// Fetch a specific committed original only after the same current
    /// reciprocal predicate and atomic two-party read as a listing.
    async fn ciphertext_inner<B: Store, C: Clock, T: Tokens, E: AssociatedEvidence>(
        &self,
        board: &Switchboard<B, C, T>,
        request: CiphertextRequest<'_>,
        verification: &Verification<'_>,
        contact: &impl Fn(&str) -> cshm::ContactCheck,
        evidence: &mut Evidence<'_, E>,
    ) -> Result<Vec<u8>, LookupError> {
        let CiphertextRequest {
            request,
            member,
            revision,
        } = request;
        let requester = board
            .requester(request.session, request.current, verification, contact)
            .await?;
        evidence.require(&requester)?;
        let candidate = board
            .candidate(
                request.session,
                request.current,
                member,
                verification,
                contact,
            )
            .await?;
        evidence.current()?;
        evidence.require(&candidate)?;
        if candidate.profile().transcript().revision != revision
            || !cgrd::matches(
                requester.profile().participant(),
                candidate.profile().participant(),
            )
            .is_match()
        {
            return Err(LookupError::ResetRequired);
        }
        if candidate.publication().ciphertext.len() > self.limits.publication_bytes {
            return Err(LookupError::Invalid);
        }
        evidence.current()?;
        board
            .confirm(&[&requester, &candidate], verification, contact)
            .await?;
        evidence.current()?;
        Ok(candidate.publication().ciphertext.clone())
    }
}

fn context(
    row: &VerifiedPresence,
    limit: usize,
    trust_revision: u64,
    associated: bool,
) -> CursorContext {
    let binding = row.binding();
    CursorContext {
        community: binding.community.clone(),
        requester: binding.member.clone(),
        generation: row.generation().into(),
        epoch: binding.epoch,
        schema: binding.schema,
        revision: row.revision(),
        query: Sha256::digest(
            serde_json::json!([
                if associated {
                    "clkp.page.associated.v1"
                } else {
                    "clkp.page.v1"
                },
                limit,
                trust_revision,
                &row.publication().signed
            ])
            .to_string(),
        )
        .into(),
    }
}
