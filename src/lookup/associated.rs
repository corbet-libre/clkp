use super::{LookupError, VerifiedPresence};

/// Additional owner evidence for an exact committed publication. Lookup does
/// not interpret it. The application supplies its concrete authoritative owner;
/// incoming requests cannot supply this implementation or a serialized verdict.
pub trait AssociatedEvidence {
    type Evidence;

    /// `None` omits a candidate before any observation is retained. A requester
    /// without evidence refuses the operation. Errors refuse the entire cut.
    fn verify(&mut self, row: &VerifiedPresence) -> Result<Option<Self::Evidence>, LookupError>;

    /// Recheck retained evidence against the owner's current authenticated
    /// material and clock, including the exact row's exclusive deadline. The
    /// owner retains that row bound with its evidence. Called after every await
    /// in the composed read, including the final atomic presence confirmation.
    fn current(&mut self, evidence: &Self::Evidence) -> Result<(), LookupError>;

    /// Exclusive Unix millisecond bound of this evidence, never a grant itself.
    fn valid_until(&self, evidence: &Self::Evidence) -> u64;
}

// No accepting implementation exists for the legacy G1-only entrypoints.
// Their absent extra owner is explicit and uses a different cursor domain.
pub(super) enum Unassociated {}
impl AssociatedEvidence for Unassociated {
    type Evidence = Self;
    fn verify(&mut self, _: &VerifiedPresence) -> Result<Option<Self>, LookupError> {
        match *self {}
    }
    fn current(&mut self, _: &Self) -> Result<(), LookupError> {
        match *self {}
    }
    fn valid_until(&self, _: &Self) -> u64 {
        match *self {}
    }
}

pub(super) struct Evidence<'a, E: AssociatedEvidence> {
    owner: Option<&'a mut E>,
    retained: Vec<E::Evidence>,
    until: u64,
}
impl Evidence<'_, Unassociated> {
    pub(super) fn partial() -> Self {
        Self {
            owner: None,
            retained: Vec::new(),
            until: u64::MAX,
        }
    }
}
impl<'a, E: AssociatedEvidence> Evidence<'a, E> {
    pub(super) fn checked(owner: &'a mut E) -> Self {
        Self {
            owner: Some(owner),
            retained: Vec::new(),
            until: u64::MAX,
        }
    }
    pub(super) fn is_checked(&self) -> bool {
        self.owner.is_some()
    }
    pub(super) fn require(&mut self, row: &VerifiedPresence) -> Result<(), LookupError> {
        if self.include(row)? {
            Ok(())
        } else {
            Err(LookupError::Associated)
        }
    }
    pub(super) fn include(&mut self, row: &VerifiedPresence) -> Result<bool, LookupError> {
        let Some(owner) = self.owner.as_mut() else {
            return Ok(true);
        };
        let Some(evidence) = owner.verify(row)? else {
            return Ok(false);
        };
        owner.current(&evidence)?;
        let until = owner.valid_until(&evidence);
        if until == 0 {
            return Err(LookupError::Associated);
        }
        self.until = self.until.min(until).min(row.deadline());
        self.retained.push(evidence);
        Ok(true)
    }
    pub(super) fn current(&mut self) -> Result<(), LookupError> {
        if let Some(owner) = self.owner.as_mut() {
            for evidence in &self.retained {
                owner.current(evidence)?;
            }
        }
        Ok(())
    }
    pub(super) fn deadline(&self, requester: u64) -> u64 {
        requester.min(self.until)
    }
}
