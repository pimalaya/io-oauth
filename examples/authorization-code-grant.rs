use std::{
    borrow::Cow,
    env,
    io::{stdin, stdout, Write},
    net::TcpStream,
    sync::Arc,
};

use http::{header::HOST, Request};
use io_oauth::v2_0::authorization_code_grant::{
    AccessTokenRequestParams, AuthorizationRequestParams, AuthorizationResponseParams,
    SendAccessTokenRequest, State,
};
use io_stream::runtimes::std::handle;
use rustls::{ClientConfig, ClientConnection, StreamOwned};
use rustls_platform_verifier::ConfigVerifierExt;
use secrecy::ExposeSecret;
use url::Url;

fn main() {
    env_logger::init();

    let client_id = match env::var("CLIENT_ID") {
        Ok(id) => id,
        Err(_) => read_line("Client ID?"),
    };

    let redirect_uri = match env::var("REDIRECT_URI") {
        Ok(uri) => uri,
        Err(_) => read_line("Redirect URI?"),
    };

    let scope = match env::var("SCOPE") {
        Ok(scopes) => scopes,
        Err(_) => read_line("Scope?"),
    };

    let mut auth_uri: Url = match env::var("AUTHORIZATION_URI") {
        Ok(url) => url.parse().unwrap(),
        Err(_) => read_line("Authorization URL?").parse().unwrap(),
    };

    let token_uri: Url = match env::var("TOKEN_URI") {
        Ok(url) => url.parse().unwrap(),
        Err(_) => read_line("Token URL?").parse().unwrap(),
    };

    let mut stream = connect(&token_uri);

    // 1. authorization request: build URL for user to browse

    let request_params = AuthorizationRequestParams {
        client_id: client_id.as_str().into(),
        redirect_uri: Some(redirect_uri.clone().into()),
        scope: scope.split_whitespace().map(Into::into).collect(),
        state: Some(Cow::Owned(State::new())),
        #[cfg(feature = "pkce")]
        pkce_code_challenge: None,
    };

    auth_uri.set_query(Some(&request_params.to_form_url_encoded_string()));

    println!();
    println!("Navigate to the following URI: {auth_uri}");
    println!();

    // 2. authorization response: extract code, check states

    let redirected_uri: Url = read_line("Redirected URI?").parse().unwrap();
    println!();

    let response_params = AuthorizationResponseParams::from_url(&redirected_uri).unwrap();

    if request_params.state != response_params.state {
        panic!("states mismatch");
    }

    // 3. access token request: send request

    let host = token_uri.host_str().unwrap();
    let port = token_uri.port_or_known_default().unwrap();
    let request = Request::post(token_uri.path()).header(HOST, format!("{host}:{port}"));

    let params = AccessTokenRequestParams {
        code: response_params.code,
        redirect_uri: Some(redirect_uri.into()),
        client_id: client_id.into(),
        #[cfg(feature = "pkce")]
        pkce_code_challenge: None,
    };

    let mut send = SendAccessTokenRequest::new(request, params).unwrap();
    let mut arg = None;

    let res = loop {
        match send.resume(arg.take()) {
            Err(io) => arg = Some(handle(&mut stream, io).unwrap()),
            Ok(Err(err)) => panic!("parse response error: {err}"),
            Ok(Ok(res)) => break res,
        }
    };

    // 4. access token response: extract access token and potential
    // refresh token

    match res {
        Ok(res) => {
            println!("access token: {:?}", res.access_token.expose_secret());
            println!();

            match res.refresh_token {
                Some(token) => println!("refresh token: {:?}", token.expose_secret()),
                None => println!("no refresh token"),
            };
        }
        Err(err) => {
            panic!("get access token error: {err:?}");
        }
    }
}

fn read_line(prompt: &str) -> String {
    print!("{prompt} ");
    stdout().flush().unwrap();

    let mut line = String::new();
    stdin().read_line(&mut line).unwrap();

    line.trim().to_owned()
}

trait StreamExt: std::io::Read + std::io::Write {}
impl<T: std::io::Read + std::io::Write> StreamExt for T {}

fn connect(url: &Url) -> Box<dyn StreamExt> {
    let domain = url.domain().unwrap();

    if url.scheme().eq_ignore_ascii_case("https") {
        let config = ClientConfig::with_platform_verifier();
        let server_name = domain.to_string().try_into().unwrap();
        let conn = ClientConnection::new(Arc::new(config), server_name).unwrap();
        let tcp = TcpStream::connect((domain.to_string(), 443)).unwrap();
        let tls = StreamOwned::new(conn, tcp);
        Box::new(tls)
    } else {
        let tcp = TcpStream::connect((domain.to_string(), 80)).unwrap();
        Box::new(tcp)
    }
}
