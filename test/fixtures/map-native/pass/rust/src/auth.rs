use axum::{extract::Request, http::StatusCode, middleware::Next, response::Response};

pub struct AuthUser {
    pub id: i64,
}

pub async fn require_auth(request: Request, next: Next) -> Result<Response, StatusCode> {
    if request.headers().get("authorization").is_none() {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(next.run(request).await)
}

pub async fn require_admin(request: Request, next: Next) -> Result<Response, StatusCode> {
    if request.headers().get("x-role").map(|v| v == "admin").unwrap_or(false) {
        return Ok(next.run(request).await);
    }
    Err(StatusCode::FORBIDDEN)
}
