use axum::{
    body::Bytes,
    extract::Path,
    http::{HeaderMap, StatusCode},
    middleware,
    routing::{delete, get, post},
    Json, Router,
};

mod auth;
mod orders;

use auth::{require_admin, require_auth, AuthUser};

#[tokio::main]
async fn main() {
    let protected = Router::new()
        .route("/me", get(me))
        .route("/notes", get(list_notes))
        .route("/notes/:id", get(get_note).delete(delete_note))
        .route_layer(middleware::from_fn(require_auth));
    let admin = Router::new()
        .route("/users/:id/role", post(set_role))
        .route_layer(middleware::from_fn(require_auth));

    let app = Router::new()
        .route("/health", get(health))
        .route("/api/login", post(login))
        .route("/api/notes", post(create_note))
        .route("/api/export", get(export))
        .route("/api/webhooks/payments", post(payments))
        .nest("/api", protected)
        .nest("/api/admin", admin);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn health() -> &'static str {
    "ok"
}

async fn login(Json(body): Json<LoginRequest>) -> Json<TokenResponse> {
    Json(auth::issue(&body.email, &body.password))
}

async fn me(user: AuthUser) -> Json<UserView> {
    Json(UserView { id: user.id })
}

async fn list_notes(user: AuthUser) -> Json<Vec<Note>> {
    Json(notes::for_owner(user.id))
}

async fn create_note(Json(body): Json<NoteRequest>) -> Json<Note> {
    Json(notes::create(body))
}

async fn get_note(Path(id): Path<i64>) -> Json<Note> {
    Json(notes::find(id))
}

async fn delete_note(Path(id): Path<i64>) -> StatusCode {
    notes::remove(id);
    StatusCode::NO_CONTENT
}

async fn export() -> Json<Vec<UserView>> {
    Json(users::all())
}

async fn set_role(Path(id): Path<i64>, Json(body): Json<RoleRequest>) -> StatusCode {
    users::set_role(id, &body.role);
    StatusCode::OK
}

async fn payments(body: Bytes) -> StatusCode {
    let event: PaymentEvent = serde_json::from_slice(&body).unwrap();
    orders::mark_paid(&event.order_id);
    StatusCode::OK
}
