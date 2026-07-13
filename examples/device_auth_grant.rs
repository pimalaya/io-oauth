use std::{
    env,
    io::{Write, stdin, stdout},
};

use io_oauth::{rfc6749::client::Oauth20ClientStd, rfc8628::auth::Oauth20RequestDeviceAuthParams};
use pimalaya_stream::tls::Tls;
use secrecy::ExposeSecret;
use url::Url;

fn main() {
    env_logger::init();

    let client_id = match env::var("CLIENT_ID") {
        Ok(id) => id,
        Err(_) => read_line("Client ID?"),
    };

    let scope = match env::var("SCOPE") {
        Ok(scopes) => scopes,
        Err(_) => read_line("Scope?"),
    };

    let device_auth_uri: Url = match env::var("DEVICE_AUTHORIZATION_URI") {
        Ok(url) => url.parse().unwrap(),
        Err(_) => read_line("Device authorization URL?").parse().unwrap(),
    };

    let token_uri: Url = match env::var("TOKEN_URI") {
        Ok(url) => url.parse().unwrap(),
        Err(_) => read_line("Token URL?").parse().unwrap(),
    };

    let tls = Tls::default();
    let mut client = Oauth20ClientStd::connect(token_uri, &tls, client_id.as_str()).unwrap();

    // 1. device authorization request: obtain device and user codes

    let params = Oauth20RequestDeviceAuthParams {
        client_id: client_id.as_str().into(),
        scope: scope.split_whitespace().map(Into::into).collect(),
    };

    let device = match client
        .request_device_authorization(&device_auth_uri, params)
        .unwrap()
    {
        Ok(device) => device,
        Err(err) => panic!("device authorization error: {err:?}"),
    };

    println!();
    println!(
        "Navigate to {} and enter the code {}",
        device.verification_uri, device.user_code
    );
    if let Some(uri) = &device.verification_uri_complete {
        println!("Or navigate directly to {uri}");
    }
    println!();

    // 2. device access token request: poll the token endpoint until
    // the user completes the flow

    match client.await_device_access_token(&tls, &device).unwrap() {
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
