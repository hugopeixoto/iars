use actix_web::{get, web, HttpResponse, Responder};
use serde::Serialize;

#[derive(Serialize)]
struct Metadata {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    code_challenge_methods_supported: Vec<String>,
}

impl Metadata {
    pub fn new(base_url: &String) -> Self {
        Metadata {
            issuer: base_url.clone(),
            authorization_endpoint: "/authorize".into(),
            token_endpoint: "/token".into(),
            code_challenge_methods_supported: vec!["S256".into()],
        }
    }
}

#[get("/metadata")]
async fn endpoint(data: web::Data<crate::AppState>) -> impl Responder {
    HttpResponse::Ok()
        .insert_header(("Content-Type", "application/json"))
        .body(serde_json::to_string(&Metadata::new(&data.config.base_url)).unwrap())
}
