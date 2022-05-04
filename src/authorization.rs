use askama::Template;
use actix_web::{get, web, HttpResponse, Responder};
use serde::Deserialize;
use rand::{thread_rng, Rng};
use std::fmt::Write;

fn generate_code() -> String {
    let mut arr = [0u8; 20];

    thread_rng().fill(&mut arr[..]);

    let mut s = String::new();

    for &b in arr.iter() {
        write!(&mut s, "{:02X}", b).unwrap();
    }

    s
}

#[derive(Template)]
#[template(path = "authorization.html")]
struct View<'a> {
    code: &'a str,
    client_id: &'a str,
    scope: &'a str,
}

#[derive(Deserialize, Debug)]
pub struct Query {
    response_type: String,
    client_id: String,
    redirect_uri: String,
    state: String,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    scope: Option<String>,
    me: Option<String>,
}

#[get("/authorize")]
async fn endpoint(query: web::Query<Query>, data: web::Data<crate::AppState>) -> impl Responder {
    if query.response_type != "code" {
        return HttpResponse::BadRequest().body("Invalid response_type");
    }

    if query.code_challenge_method != Some("S256".into()) || query.code_challenge_method.is_none() {
        return HttpResponse::BadRequest().body("Invalid code_challenge_method");
    }

    if query.me.is_some() && query.me.as_ref().unwrap() != &data.config.me {
        return HttpResponse::BadRequest().body("Unknown identity");
    }

    // fetch client_id
    // validate redirect_uri with client_id

    let req = crate::AuthorizationRequest {
        authorization_code: generate_code(),
        client_id: query.client_id.clone(),
        redirect_uri: query.redirect_uri.clone(),
        code_challenge: query.code_challenge.clone(),
        code_challenge_method: query.code_challenge_method.clone(),
        state: query.state.clone(),
    };

    data.register_authorization_request(req.clone());

    HttpResponse::Ok().body(View {
        code: &req.authorization_code,
        client_id: &query.client_id,
        scope: &query.scope.as_ref().unwrap_or(&"".into()),
    }.render().unwrap())
}
