use actix_web::{post, web, App, HttpResponse, HttpServer, Responder};
use std::sync::Mutex;
use serde::Deserialize;
use sha2::Digest;
use base64::{decode_config, URL_SAFE};

mod utils;
mod authorization;
mod authorize;
mod consent;
mod metadata;

#[derive(Default)]
struct CircuitBreaker {
    broken: bool,
    attempts: usize,
}

impl CircuitBreaker {
    pub fn fail(&mut self) {
        self.attempts += 1;

        if self.attempts >= 3 {
            self.broken = true;
        }
    }

    pub fn reset(&mut self) {
        self.attempts = 0;
        self.broken = false;
    }
}

#[derive(Clone)]
struct AuthorizationRequest {
    authorization_code: String,
    client_id: String,
    redirect_uri: String,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    state: String,
}

impl AuthorizationRequest {
    pub fn verify(&self, code_verifier: &Option<String>) -> bool {
        if self.code_challenge_method.is_none() && code_verifier.is_none() {
            return true;
        }

        if self.code_challenge_method == Some("S256".into()) && code_verifier.is_some() {
            let hashed = sha2::Sha256::digest(code_verifier.as_ref().unwrap());
            let decoded = decode_config(self.code_challenge.as_ref().unwrap(), URL_SAFE).unwrap();

            return decoded == hashed.as_slice();
        }

        false
    }
}

struct AuthorizationChannel {
   receiver: Mutex<tokio::sync::mpsc::Receiver<bool>>,
   sender: tokio::sync::mpsc::Sender<bool>,
   code: Mutex<Option<String>>,
}

struct AppState {
    breaker: Mutex<CircuitBreaker>,
    config: Config,
    authorization_requests: Mutex<Vec<AuthorizationRequest>>,
    authorization_channel: AuthorizationChannel,
}

impl AppState {
    fn broken(&self) -> bool {
        let breaker = self.breaker.lock().unwrap();

        breaker.broken
    }

    fn fail(&self) {
        let mut breaker = self.breaker.lock().unwrap();

        breaker.fail();
    }

    fn reset(&self) {
        let mut breaker = self.breaker.lock().unwrap();

        breaker.reset();
    }


    fn register_authorization_request(&self, request: AuthorizationRequest) {
        let mut requests = self.authorization_requests.lock().unwrap();

        requests.push(request);
    }

    fn consume_authorization_request(&self, code: &String) -> Option<AuthorizationRequest> {
        let mut requests = self.authorization_requests.lock().unwrap();

        if let Some(pos) = requests.iter().position(|r| r.authorization_code == *code) {
            Some(requests.remove(pos))
        } else {
            None
        }
    }
}

#[derive(Deserialize)]
struct Form {
    grant_type: Option<String>,
    code: String,
    client_id: String,
    redirect_uri: String,
    code_verifier: Option<String>,
}

#[post("/authorize")]
async fn token(form: web::Form<Form>, data: web::Data<AppState>) -> impl Responder {
    if form.grant_type.as_ref().unwrap_or(&"authorization_code".into()) != "authorization_code" {
        println!("POST /authorize: invalid grant_type {:?}", form.grant_type);
        return HttpResponse::BadRequest().body("Invalid grant_type");
    }

    let req = data.consume_authorization_request(&form.code);

    if req.is_none() {
        println!("POST /authorize: invalid code {}", form.code);
        return HttpResponse::BadRequest().body("Invalid code");
    }

    let req = req.unwrap();

    if req.client_id != form.client_id {
        println!("POST /authorize: invalid client_id {} (expected {})", form.client_id, req.client_id);
        return HttpResponse::BadRequest().body("Invalid client_id");
    }

    if req.redirect_uri != form.redirect_uri {
        println!("POST /authorize: invalid redirect_uri {} (expected {})", form.redirect_uri, req.redirect_uri);
        return HttpResponse::BadRequest().body("Invalid redirect_uri");
    }

    if !req.verify(&form.code_verifier) {
        println!("POST /authorize: invalid code_verifier {:?}", form.code_verifier);
        return HttpResponse::BadRequest().body("Invalid code_verifier");
    }

    println!("POST /authorize: success");
    HttpResponse::Ok()
        .insert_header(("Content-Type", "application/json"))
        .body(format!("{{\"me\":\"{}\"}}", data.config.me))
}

#[derive(Deserialize, Clone)]
struct Config {
    unifiedpush_endpoint: String,
    me: String,
    base_url: String,
    listen_address: String,
    listen_port: u16,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let content = std::fs::read_to_string(std::env::var("IARS_CONFIG_FILE").unwrap())?;
    let config: Config = toml::from_str(&content)?;

    let (tx, rx) = tokio::sync::mpsc::channel(100);

    let data = web::Data::new(AppState {
        breaker: Mutex::new(CircuitBreaker::default()),
        config: config.clone(),
        authorization_requests: Mutex::new(vec![]),
        authorization_channel: AuthorizationChannel {
            receiver: Mutex::new(rx),
            sender: tx,
            code: Mutex::new(None),
        },
    });

    HttpServer::new(move || {
        App::new()
            .app_data(data.clone())
            .service(metadata::endpoint)
            .service(authorization::endpoint)
            .service(authorize::endpoint)
            .service(consent::endpoint)
            .service(token)
    })
    .bind((config.listen_address, config.listen_port))?
        .run()
        .await
}
