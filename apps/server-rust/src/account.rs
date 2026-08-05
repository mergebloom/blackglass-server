use crate::{
    db::RegistrationResult,
    server::{AppState, RegistrationError, db_task, register_account, request_source},
};
use axum::{
    Json, Router,
    extract::{ConnectInfo, DefaultBodyLimit, State},
    http::{HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";

pub(crate) fn router() -> Router<AppState> {
    Router::new()
        .route("/account", get(shell))
        .route("/account/styles.css", get(styles))
        .route("/account/app.js", get(script))
        .route("/account/logo.png", get(logo))
        .route("/account/api/registration", get(registration_status))
        .route("/account/api/signup", post(signup))
        .layer(DefaultBodyLimit::max(4 * 1024))
        .layer(middleware::from_fn(security_headers))
}

async fn security_headers(request: axum::extract::Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert("content-security-policy", HeaderValue::from_static(CSP));
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

async fn shell() -> Html<&'static str> {
    Html(ACCOUNT_HTML)
}

async fn styles() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        ACCOUNT_CSS,
    )
}

async fn script() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        ACCOUNT_JS,
    )
}

async fn logo() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "image/png")],
        crate::admin::ADMIN_LOGO,
    )
}

#[derive(Serialize)]
struct RegistrationStatus {
    enabled: bool,
}

async fn registration_status(State(state): State<AppState>) -> Response {
    match db_task(&state, |db| db.self_registration_enabled()).await {
        Ok(enabled) => Json(RegistrationStatus { enabled }).into_response(),
        Err(_) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}

#[derive(Deserialize)]
struct SignupRequest {
    email: String,
    name: String,
    password: String,
}

#[derive(Serialize)]
struct SignupResponse {
    created: bool,
    message: &'static str,
}

async fn signup(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    Json(request): Json<SignupRequest>,
) -> Response {
    let source = request_source(&state.config, peer, &headers);
    match register_account(
        &state,
        source,
        request.email,
        request.name,
        request.password,
    )
    .await
    {
        Ok(RegistrationResult::Created(_)) => (
            StatusCode::CREATED,
            Json(SignupResponse {
                created: true,
                message: "Account created. You can now sign in from Blackglass Bridge.",
            }),
        )
            .into_response(),
        Ok(RegistrationResult::Disabled) => (
            StatusCode::FORBIDDEN,
            Json(SignupResponse {
                created: false,
                message: "Self-registration is currently disabled.",
            }),
        )
            .into_response(),
        Ok(RegistrationResult::Unavailable) => (
            StatusCode::CONFLICT,
            Json(SignupResponse {
                created: false,
                message: "Registration could not be completed with those details.",
            }),
        )
            .into_response(),
        Err(RegistrationError::Invalid(message)) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"created":false,"message":message})),
        )
            .into_response(),
        Err(RegistrationError::RateLimited) => (
            StatusCode::TOO_MANY_REQUESTS,
            [(header::RETRY_AFTER, "60")],
            Json(SignupResponse {
                created: false,
                message: "Too many registration attempts; try again later.",
            }),
        )
            .into_response(),
        Err(RegistrationError::Unavailable) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(SignupResponse {
                created: false,
                message: "Registration is temporarily unavailable.",
            }),
        )
            .into_response(),
    }
}

pub(crate) const ACCOUNT_HTML: &str = include_str!("../account/index.html");
pub(crate) const ACCOUNT_CSS: &str = include_str!("../account/styles.css");
pub(crate) const ACCOUNT_JS: &str = include_str!("../account/app.js");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_account_assets_are_dark_responsive_and_secret_free() {
        assert!(ACCOUNT_HTML.contains("Create your Blackglass account"));
        assert!(ACCOUNT_HTML.contains("autocomplete=\"new-password\""));
        assert!(ACCOUNT_CSS.contains("color-scheme: dark"));
        assert!(ACCOUNT_CSS.contains("@media"));
        assert!(ACCOUNT_JS.contains("/account/api/registration"));
        assert!(ACCOUNT_JS.contains("/account/api/signup"));
        for forbidden in ["password_hash", "admin_session", "SELFHOST_"] {
            assert!(!ACCOUNT_HTML.contains(forbidden));
            assert!(!ACCOUNT_JS.contains(forbidden));
        }
    }
}
