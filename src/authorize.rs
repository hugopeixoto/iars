use actix_web::{post, web, HttpResponse, HttpRequest, Responder};
use serde::Deserialize;

fn build_answer_url(base_url: &str, code: &str, authorized: bool) -> String {
    let mut url = url::Url::parse(base_url).unwrap();
    url.set_path("answer");

    url.query_pairs_mut().append_pair("authorized", if authorized { "true" } else { "false" });
    url.query_pairs_mut().append_pair("code", code);

    url.into()
}

async fn push_notification(ep: &str, base_url: &str, code: &str, client_id: &str) {
    reqwest::Client::new()
        .post(ep)
        .header("Actions", format!("http, Authorize, url={}; http, Deny, url={}", build_answer_url(&base_url, &code, true), build_answer_url(&base_url, &code, false)))
        .header("Title", "IndieAuth attempt")
        .body(format!("Website: {}", client_id))
        .send()
        .await
        .unwrap();
}

#[derive(Deserialize)]
struct Form {
    client_id: String,
    redirect_uri: String,
    state: String,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    // scope: Option<String>,
}

#[post("/consent")]
async fn endpoint(form: web::Form<Form>, data: web::Data<crate::AppState>, req: HttpRequest) -> impl Responder {
    println!("POST /consent {}", req.connection_info().realip_remote_addr().unwrap_or("<no-ip>"));

    if data.broken() {
        println!("  circuit-broken");
        return HttpResponse::TooManyRequests().body("too many failed authentication attempts");
    }

    let req = crate::AuthorizationRequest {
        authorization_code: crate::utils::generate_code(),
        client_id: form.client_id.clone(),
        redirect_uri: form.redirect_uri.clone(),
        code_challenge: form.code_challenge.clone(),
        code_challenge_method: form.code_challenge_method.clone(),
        state: form.state.clone(),
    };

    data.register_authorization_request(req.clone());

    let code = crate::utils::generate_code();

    {
        // TODO: this should probably be per authorization request or something.
        let mut stored_code = data.authorization_channel.code.lock().unwrap();
        *stored_code = Some(code.clone());
    }

    push_notification(
        &data.config.unifiedpush_endpoint,
        &data.config.base_url,
        &code,
        &req.client_id,
    ).await;

    // TODO: read 30s from config, maybe?
    let response = tokio::time::timeout(std::time::Duration::from_millis(30_000), data.authorization_channel.receiver.lock().unwrap().recv()).await;

    match response {
        Err(_) | Ok(None) => {
            println!("  timeout");

            data.fail();

            HttpResponse::RequestTimeout().finish()
        },
        Ok(Some(response)) => {
            println!("  user answer: {}", response);

            data.reset();

            if response {
                let mut url = url::Url::parse(&req.redirect_uri).unwrap();

                url.query_pairs_mut().append_pair("code", &req.authorization_code);
                url.query_pairs_mut().append_pair("state", &req.state);

                HttpResponse::SeeOther()
                    .insert_header(("Location", url.as_str()))
                    .finish()
            } else {
                HttpResponse::Unauthorized()
                    .finish()
            }
        }
    }
}
