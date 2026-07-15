//! The ways a client obtains its registration, in preference order.

/// The ways a client obtains its registration against an
/// authorization server, declared in preference order.
///
/// Dynamic registration comes first: it spares any provider console
/// but requires the server to advertise a registration endpoint in
/// its RFC 8414 metadata. Reusing the registration of a well-known
/// public client (client id, and secret when issued, being public
/// knowledge) needs no server support but borrows another
/// application's identity. Registering manually through the
/// provider's console is the universal fallback. The derived order
/// follows the declaration order, so pick lists sort by it.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Oauth20ClientSource {
    /// Register dynamically against the server's advertised
    /// registration endpoint (this RFC).
    DynamicRegistration,
    /// Reuse the registration of a well-known public client.
    PublicClient,
    /// Register manually with the provider and configure the issued
    /// credentials by hand.
    Manual,
}

#[cfg(test)]
mod tests {
    use crate::rfc7591::source::Oauth20ClientSource;

    #[test]
    fn client_sources_order_by_preference() {
        let mut sources = [
            Oauth20ClientSource::Manual,
            Oauth20ClientSource::DynamicRegistration,
            Oauth20ClientSource::PublicClient,
        ];
        sources.sort();

        assert_eq!(
            sources,
            [
                Oauth20ClientSource::DynamicRegistration,
                Oauth20ClientSource::PublicClient,
                Oauth20ClientSource::Manual,
            ]
        );
    }
}
