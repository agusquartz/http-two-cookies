use axum::{
    extract::Json,
    response::IntoResponse,
    http::StatusCode,
};
use serde::Deserialize;
use tower_cookies::{Cookies, Cookie};
use crate::auth::jwt::create_jwt;
use crate::auth::csrf::generate_csrf;

/// Structure representing the login request payload.
///
/// # Fields
/// - `username`: The user's login name
/// - `password`: The user's password
#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

/// Handles user login.
///
/// Steps performed:
/// 1. Validate username and password (demo validation in this example).
/// 2. Generate a JWT token for authenticated sessions.
/// 3. Generate a CSRF token for request protection.
/// 4. Set cookies:
///    - `jwt` → HttpOnly, Secure, SameSite=None
///    - `csrf` → Secure, SameSite=None (accessible by JS)
/// 5. Return the CSRF token in JSON response.
///
/// # Example
/// ```http
/// POST /auth/login
/// Content-Type: application/json
///
/// { "username": "user", "password": "password" }
///
/// Response:
/// { "csrf": "<csrf-token>" }
/// ```
pub async fn login(
    cookies: Cookies,
    Json(payload): Json<LoginRequest>,
) -> Result<impl IntoResponse, impl IntoResponse> {

    // -----------------------------
    // 1. Validate credentials (demo)
    // -----------------------------
    if payload.username != "user" || payload.password != "password" {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "Invalid credentials"})),
        ));
    }

    // -----------------------------
    // 2. Create JWT
    // -----------------------------
    let ttl_seconds: u64 = env::var("JWT_TTL_SECONDS")
        .unwrap_or_else(|_| "86400".to_string()) // fallback 24h
        .parse()
        .expect("JWT_TTL_SECONDS must be a valid number");

    let token = create_jwt(&payload.username, ttl_seconds)
        .map_err(|_| (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "Token creation failed"}))
        ))?;

    // -----------------------------
    // 3. Create CSRF token
    // -----------------------------
    let csrf_token = generate_csrf();

    // -----------------------------
    // 4. Set cookies
    // -----------------------------
    // JWT cookie (HttpOnly)
    let mut jwt_cookie = Cookie::new("jwt", token);
    jwt_cookie.set_path("/");
    jwt_cookie.set_http_only(true);
    jwt_cookie.set_secure(true);
    jwt_cookie.set_same_site(tower_cookies::cookie::SameSite::None);
    cookies.add(jwt_cookie);

    // CSRF cookie (accessible by JS)
    let mut csrf_cookie = Cookie::new("csrf", csrf_token.clone());
    csrf_cookie.set_path("/");
    csrf_cookie.set_secure(true);
    csrf_cookie.set_same_site(tower_cookies::cookie::SameSite::None);
    cookies.add(csrf_cookie);

    // -----------------------------
    // 5. Return CSRF token in JSON
    // -----------------------------
    Ok(Json(serde_json::json!({"csrf": csrf_token})))
}