use actix_web::{post, web, HttpResponse, Responder};
use libotp::{validate_totp};
use serde::Deserialize;

#[derive(Deserialize)]
struct Form {
    code: String,
    totp: u32,
}

#[post("/consent")]
async fn endpoint(form: web::Form<Form>, data: web::Data<crate::AppState>) -> impl Responder {
    if data.broken() {
        return HttpResponse::TooManyRequests().body("too many failed authentication attempts");
    }

    if !validate_totp(form.totp, 1, &data.config.totp_secret, 6, 30, 0).unwrap_or(false) {
        data.fail();

        return HttpResponse::Forbidden().body("wrong authorization code");
    }

    let req = data.find_authorization_request(&form.code);
    if req.is_none() {
        return HttpResponse::Forbidden().body("unknown code");
    }
    let req = req.unwrap();

    let mut url = url::Url::parse(&req.redirect_uri).unwrap();

    url.query_pairs_mut().append_pair("code", &req.authorization_code);
    url.query_pairs_mut().append_pair("state", &req.state);

    HttpResponse::SeeOther()
        .insert_header(("Location", url.as_str()))
        .finish()
}
