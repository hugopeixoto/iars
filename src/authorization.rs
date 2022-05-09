use askama::Template;
use actix_web::{get, web, HttpResponse, Responder};
use serde::Deserialize;

#[derive(Template)]
#[template(path = "authorization.html")]
struct View<'a> {
    client_id: &'a String,
    redirect_uri: &'a String,
    state: &'a String,
    code_challenge: Option<&'a String>,
    code_challenge_method: Option<&'a String>,
    scope: Option<&'a String>,
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

    if !(query.code_challenge_method == Some("S256".into()) || query.code_challenge_method.is_none()) {
        return HttpResponse::BadRequest().body("Invalid code_challenge_method");
    }

    if query.me.is_some() && query.me.as_ref().unwrap() != &data.config.me {
        return HttpResponse::BadRequest().body("Unknown identity");
    }

    // fetch client_id and validate redirect_uri

    HttpResponse::Ok().body(View {
        client_id: &query.client_id,
        redirect_uri: &query.redirect_uri,
        state: &query.state,
        scope: query.scope.as_ref(),
        code_challenge: query.code_challenge.as_ref(),
        code_challenge_method: query.code_challenge_method.as_ref(),
    }.render().unwrap())
}
