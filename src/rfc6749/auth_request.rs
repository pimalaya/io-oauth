//! Authorization request (RFC 6749 section 4.1.1).
//!
//! Builds the authorization URL the end user browses to, opening the
//! authorization code grant; the redirect back is parsed by the auth
//! response sibling module.

use alloc::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
    string::String,
    vec::Vec,
};

use url::Url;

use crate::{rfc6749::state::Oauth20State, rfc7636::pkce::Oauth20PkceCodeChallenge};

/// The authorization request parameters from the authorization code grant.
///
/// Refs: <https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1>
pub struct Oauth20AuthRequestParams<'a> {
    /// The client identifier.
    ///
    /// Refs: <https://datatracker.ietf.org/doc/html/rfc6749#section-2.2>
    pub client_id: Cow<'a, str>,
    /// The absolute URI the server redirects the user-agent back to.
    ///
    /// Refs: <https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.2>
    pub redirect_uri: Option<Cow<'a, str>>,
    /// The requested access scope, as space-delimited tokens.
    ///
    /// Refs: <https://datatracker.ietf.org/doc/html/rfc6749#section-3.3>
    // TODO: validate scope tokens?
    pub scope: BTreeSet<Cow<'a, str>>,
    /// The opaque CSRF value echoed back on the callback.
    ///
    /// Refs: <https://datatracker.ietf.org/doc/html/rfc6749#section-10.12>
    pub state: Option<Cow<'a, Oauth20State>>,
    /// The PKCE code challenge, when the flow uses PKCE (RFC 7636).
    pub pkce_code_challenge: Option<Cow<'a, Oauth20PkceCodeChallenge>>,
    /// The resources the token is meant for, one `resource` parameter each.
    ///
    /// A server bound to a resource refuses a request without it, with the
    /// `invalid_target` error. Empty sends none; an extra or an endpoint
    /// parameter named `resource` replaces them all.
    ///
    /// Refs: <https://datatracker.ietf.org/doc/html/rfc8707#section-2>
    pub resource: Vec<Url>,
    /// Extra query parameters appended to the authorization URL.
    ///
    /// Carries provider-specific parameters not covered by the typed fields
    /// (Google's `access_type`, Microsoft's `tenant`, ...). Entries override
    /// equally-named typed defaults but lose to parameters already present in
    /// the endpoint URL.
    pub extras: BTreeMap<Cow<'a, str>, Cow<'a, str>>,
}

impl Oauth20AuthRequestParams<'_> {
    /// Builds the authorization URL from the typed fields.
    ///
    /// `extras` override the typed defaults, and query parameters already
    /// present in `endpoint` take final precedence.
    // SAFETY: exposes the state and the PKCE code verifier
    pub fn build_url(&self, endpoint: &Url) -> Url {
        let mut params: BTreeMap<String, String> = BTreeMap::new();

        params.insert("response_type".into(), "code".into());
        params.insert("client_id".into(), self.client_id.as_ref().into());

        if let Some(state) = &self.state {
            params.insert(
                "state".into(),
                String::from_utf8_lossy(state.expose()).into_owned(),
            );
        }

        if let Some(uri) = &self.redirect_uri {
            params.insert("redirect_uri".into(), uri.as_ref().into());
        }

        if !self.scope.is_empty() {
            let mut scope = String::new();
            let mut glue = "";

            for token in &self.scope {
                scope.push_str(glue);
                scope.push_str(token);
                glue = " ";
            }

            params.insert("scope".into(), scope);
        }

        if let Some(challenge) = &self.pkce_code_challenge {
            params.insert("code_challenge".into(), challenge.encode().into_owned());
            params.insert(
                "code_challenge_method".into(),
                challenge.method.as_str().into(),
            );
        }

        for (k, v) in &self.extras {
            params.insert(k.as_ref().into(), v.as_ref().into());
        }

        for (k, v) in endpoint.query_pairs() {
            params.insert(k.into_owned(), v.into_owned());
        }

        let mut url = endpoint.clone();
        let mut qm = url.query_pairs_mut();
        qm.clear();
        qm.extend_pairs(params.iter().map(|(k, v)| (k.as_str(), v.as_str())));

        if !params.contains_key("resource") {
            for resource in &self.resource {
                qm.append_pair("resource", resource.as_str());
            }
        }

        drop(qm);
        url
    }
}

#[cfg(test)]
mod tests {
    use alloc::{
        borrow::Cow,
        collections::{BTreeMap, BTreeSet},
        string::String,
        vec,
        vec::Vec,
    };

    use url::Url;

    use crate::rfc6749::auth_request::*;

    fn params(resource: Vec<Url>) -> Oauth20AuthRequestParams<'static> {
        Oauth20AuthRequestParams {
            client_id: Cow::Borrowed("client"),
            redirect_uri: None,
            scope: BTreeSet::new(),
            state: None,
            pkce_code_challenge: None,
            resource,
            extras: BTreeMap::new(),
        }
    }

    fn resources_of(url: &Url) -> Vec<String> {
        url.query_pairs()
            .filter(|(k, _)| k == "resource")
            .map(|(_, v)| v.into_owned())
            .collect()
    }

    #[test]
    fn every_resource_is_its_own_parameter() {
        let endpoint = Url::parse("https://example.test/authorize").unwrap();
        let params = params(vec![
            Url::parse("https://api.example.test/jmap").unwrap(),
            Url::parse("https://dav.example.test/").unwrap(),
        ]);

        assert_eq!(
            resources_of(&params.build_url(&endpoint)),
            ["https://api.example.test/jmap", "https://dav.example.test/"]
        );
    }

    #[test]
    fn a_resource_extra_replaces_the_typed_resources() {
        let endpoint = Url::parse("https://example.test/authorize").unwrap();
        let mut params = params(vec![Url::parse("https://typed.example.test/").unwrap()]);
        params
            .extras
            .insert("resource".into(), "https://extra.example.test/".into());

        assert_eq!(
            resources_of(&params.build_url(&endpoint)),
            ["https://extra.example.test/"]
        );
    }
}
