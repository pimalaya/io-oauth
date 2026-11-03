//! JWT bearer client credentials example (RFC 7523 section 2.2).
//!
//! Runs the client credentials grant authenticated by a signed JWT
//! client assertion instead of a client secret: the fully headless
//! flow used by Microsoft Entra certificate credentials. The private
//! key signs the assertion locally; no secret ever transits.
//!
//! Inputs come from the environment or interactive prompts:
//! CLIENT_ID, TOKEN_URI, SCOPE, KEY_PATH (PKCS#8 or PKCS#1 PEM
//! private key) and the optional CERT_PATH (PEM or DER certificate,
//! used to derive the x5t thumbprint Microsoft requires).
//!
//! The Google variant (RFC 7523 section 2.1, a service account
//! assertion used as the authorization grant itself, with the scopes
//! and the impersonated user inside the claims) is one call away:
//! sign the claims the same way, then exchange them with
//! `Oauth20ClientStd::request_jwt_bearer_grant`.

use std::{
    env, fs,
    io::{Write, stdin, stdout},
    time::Duration,
};

use base64_codec::codec::Base64Codec;
use io_oauth::{
    client::Oauth20ClientStd,
    rfc7523::{assertion::*, client_auth::*},
};
use pimalaya_stream::tls::Tls;
use secrecy::ExposeSecret;
use url::Url;

fn main() {
    env_logger::init();

    let client_id = match env::var("CLIENT_ID") {
        Ok(id) => id,
        Err(_) => read_line("Client ID?"),
    };

    let token_uri: Url = match env::var("TOKEN_URI") {
        Ok(url) => url.parse().unwrap(),
        Err(_) => read_line("Token URL?").parse().unwrap(),
    };

    let scope = match env::var("SCOPE") {
        Ok(scopes) => scopes,
        Err(_) => read_line("Scope? (Microsoft: https://graph.microsoft.com/.default)"),
    };

    let key_path = match env::var("KEY_PATH") {
        Ok(path) => path,
        Err(_) => read_line("Private key PEM path?"),
    };

    let cert_path = match env::var("CERT_PATH") {
        Ok(path) => Some(path),
        Err(_) => match read_line("Certificate path? (empty to skip x5t)") {
            path if path.is_empty() => None,
            path => Some(path),
        },
    };

    // NOTE: step 1, load the signing key and derive the certificate
    // thumbprint where a certificate is given

    let pem = fs::read_to_string(&key_path).unwrap();
    let key = match Oauth20JwtBearerKey::from_pkcs8_pem(&pem) {
        Ok(key) => key,
        Err(_) => Oauth20JwtBearerKey::from_pkcs1_pem(&pem).unwrap(),
    };

    let x5t = cert_path.map(|path| {
        let bytes = fs::read(path).unwrap();
        x5t_from_der(&cert_der(bytes))
    });

    // NOTE: step 2, sign the client assertion: iss and sub are both
    // the client, aud defaults to the token endpoint, iat and exp
    // come from the clock through the std client helper

    let mut client =
        Oauth20ClientStd::connect(token_uri, &Tls::default(), client_id.as_str()).unwrap();

    let jti = format!("{:x}", std::process::id());
    let claims = Oauth20JwtBearerClaims {
        iss: client_id.as_str().into(),
        sub: Some(client_id.as_str().into()),
        jti: Some(jti.as_str().into()),
        ..Default::default()
    };

    let assertion = client
        .sign_jwt_bearer_assertion(&key, claims, x5t.as_deref(), Duration::from_secs(600))
        .unwrap();

    // NOTE: step 3, exchange the assertion for an access token: the
    // scope rides the request body, not the claims

    let params = Oauth20JwtBearerClientCredentialsRequestParams {
        client_id: Some(client_id.as_str().into()),
        scope: scope.split_whitespace().map(Into::into).collect(),
        client_assertion: assertion,
    };

    match client
        .request_jwt_bearer_client_credentials(params)
        .unwrap()
    {
        Ok(res) => {
            println!("access token: {:?}", res.access_token.expose_secret());
        }
        Err(err) => {
            panic!("get access token error: {err:?}");
        }
    }
}

/// Returns the DER bytes of a PEM or DER encoded certificate.
fn cert_der(bytes: Vec<u8>) -> Vec<u8> {
    let Ok(text) = core::str::from_utf8(&bytes) else {
        return bytes;
    };

    if !text.contains("-----BEGIN") {
        return bytes;
    }

    let body: String = text
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();

    let mut der = Vec::new();
    assert!(Base64Codec::default().decode_vec(body.as_bytes(), &mut der));
    der
}

fn read_line(prompt: &str) -> String {
    print!("{prompt} ");
    stdout().flush().unwrap();

    let mut line = String::new();
    stdin().read_line(&mut line).unwrap();

    line.trim().to_owned()
}
