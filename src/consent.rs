use actix_web::{post, web, HttpResponse, HttpRequest, Responder};
use serde::Deserialize;

#[derive(Deserialize)]
struct Query {
    code: String,
    authorized: bool,
}

#[post("/answer")]
async fn endpoint(query: web::Query<Query>, data: web::Data<crate::AppState>, req: HttpRequest) -> impl Responder {
    println!("POST /answer {}", req.connection_info().realip_remote_addr().unwrap_or("<no-ip>"));

    {
        let code = data.authorization_channel.code.lock().unwrap();

        if Some(query.code.clone()) != *code {
            return HttpResponse::BadRequest().finish();
        }
    }

    data.authorization_channel.sender.send(query.authorized).await.unwrap();

    HttpResponse::Ok()
        .finish()
}
