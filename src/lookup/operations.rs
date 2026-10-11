use super::*;

pub struct CiphertextRequest<'a> {
    pub request: PageRequest<'a>,
    pub member: &'a str,
    pub revision: u64,
}

impl<S: Store, R: Tokens> Lookup<S, R> {
    /// Original G1/device selection scope. A complete application admission
    /// owner must use `page_with` for its associated evidence.
    pub async fn page<B: Store, C: Clock, T: Tokens>(
        &self,
        board: &Switchboard<B, C, T>,
        request: PageRequest<'_>,
        verification: &Verification<'_>,
        contact: &impl Fn(&str) -> cshm::ContactCheck,
    ) -> Result<Matches, LookupError> {
        self.page_inner(
            board,
            request,
            verification,
            contact,
            &mut Evidence::partial(),
        )
        .await
    }

    /// Check concrete associated owner evidence before retaining observations,
    /// and retain those capabilities through the final atomic presence cut.
    pub async fn page_with<B: Store, C: Clock, T: Tokens, E: AssociatedEvidence>(
        &self,
        board: &Switchboard<B, C, T>,
        request: PageRequest<'_>,
        verification: &Verification<'_>,
        contact: &impl Fn(&str) -> cshm::ContactCheck,
        owner: &mut E,
    ) -> Result<Matches, LookupError> {
        self.page_inner(
            board,
            request,
            verification,
            contact,
            &mut Evidence::checked(owner),
        )
        .await
    }

    pub async fn watch<B: Store, C: Clock, T: Tokens>(
        &self,
        board: &Switchboard<B, C, T>,
        request: WatchRequest<'_>,
        verification: &Verification<'_>,
        contact: &impl Fn(&str) -> cshm::ContactCheck,
    ) -> Result<Delta, LookupError> {
        self.watch_inner(
            board,
            request,
            verification,
            contact,
            &mut Evidence::partial(),
        )
        .await
    }

    pub async fn watch_with<B: Store, C: Clock, T: Tokens, E: AssociatedEvidence>(
        &self,
        board: &Switchboard<B, C, T>,
        request: WatchRequest<'_>,
        verification: &Verification<'_>,
        contact: &impl Fn(&str) -> cshm::ContactCheck,
        owner: &mut E,
    ) -> Result<Delta, LookupError> {
        self.watch_inner(
            board,
            request,
            verification,
            contact,
            &mut Evidence::checked(owner),
        )
        .await
    }

    pub async fn ciphertext<B: Store, C: Clock, T: Tokens>(
        &self,
        board: &Switchboard<B, C, T>,
        request: PageRequest<'_>,
        owner: (&str, u64),
        verification: &Verification<'_>,
        contact: &impl Fn(&str) -> cshm::ContactCheck,
    ) -> Result<Vec<u8>, LookupError> {
        self.ciphertext_inner(
            board,
            CiphertextRequest {
                request,
                member: owner.0,
                revision: owner.1,
            },
            verification,
            contact,
            &mut Evidence::partial(),
        )
        .await
    }

    pub async fn ciphertext_with<B: Store, C: Clock, T: Tokens, E: AssociatedEvidence>(
        &self,
        board: &Switchboard<B, C, T>,
        request: CiphertextRequest<'_>,
        verification: &Verification<'_>,
        contact: &impl Fn(&str) -> cshm::ContactCheck,
        owner: &mut E,
    ) -> Result<Vec<u8>, LookupError> {
        self.ciphertext_inner(
            board,
            request,
            verification,
            contact,
            &mut Evidence::checked(owner),
        )
        .await
    }
}
