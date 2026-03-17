use axum::{
    middleware::Next,
    response::{IntoResponse, Response},
    http::{StatusCode, Request},
    body::Body,
};
use subtle::ConstantTimeEq;
use tower_cookies::Cookies;

use crate::auth::jwt::verify_jwt;

/// Middleware for authenticating requests using JWT and CSRF protection.
///
/// This middleware performs:
/// 1. JWT verification from the "jwt" cookie.
/// 2. CSRF token verification from the "csrf" cookie and "X-CSRF-Token" header.
/// 3. Attaches the JWT claims into the request extensions for downstream handlers.
///
/// # Notes
/// - JWT cookie must be HttpOnly and valid.
/// - CSRF cookie must match the CSRF header in a constant-time comparison to prevent timing attacks.
/// - If any validation fails, the request returns 401 Unauthorized or 403 Forbidden.
pub async fn auth_middleware(
    cookies: Cookies,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    // -----------------------------
    // 1. Verify JWT cookie
    // -----------------------------
    let jwt_cookie = match cookies.get("jwt") {
        Some(cookie) => cookie,
        None => return (StatusCode::UNAUTHORIZED, "Missing JWT cookie").into_response(),
    };

    let jwt_claims = match verify_jwt(jwt_cookie.value()) {
        Ok(claims) => claims,
        Err(_) => return (StatusCode::UNAUTHORIZED, "Invalid JWT").into_response(),
    };

    // -----------------------------
    // 2. Verify CSRF token
    // -----------------------------
    // Get CSRF cookie
    let csrf_cookie = match cookies.get("csrf") {
        Some(cookie) => cookie,
        None => return (StatusCode::UNAUTHORIZED, "Missing CSRF cookie").into_response(),
    };

    // Get CSRF token from request header
    let csrf_header_value = match request
        .headers()
        .get("x-csrf-token")
        .and_then(|h| h.to_str().ok())
    {
        Some(token) => token.to_string(),
        None => return (StatusCode::FORBIDDEN, "Missing X-CSRF-Token header").into_response(),
    };

    // Quick length check to avoid timing differences
    if csrf_cookie.value().len() != csrf_header_value.len() {
        return (StatusCode::FORBIDDEN, "CSRF token mismatch").into_response();
    }

    // Constant-time comparison to prevent timing attacks
    let tokens_match = csrf_cookie
        .value()
        .as_bytes()
        .ct_eq(csrf_header_value.as_bytes())
        .unwrap_u8();

    if tokens_match != 1 {
        return (StatusCode::FORBIDDEN, "CSRF token mismatch").into_response();
    }

    // -----------------------------
    // 3. Attach JWT claims to request
    // -----------------------------
    request.extensions_mut().insert(jwt_claims);

    // -----------------------------
    // 4. Continue to the next handler
    // -----------------------------
    next.run(request).await.into_response()
}