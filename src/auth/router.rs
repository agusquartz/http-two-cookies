use axum::{
    extract::Extension,
    routing::{get, post},
    Json,
    Router,
    middleware::from_fn,
};
use crate::auth::jwt::Claims;
use crate::auth::handlers::login;
use crate::auth::middleware::auth_middleware;

/// Handler that returns the JWT claims of the authenticated user.
///
/// Extracts the claims stored in the request extensions by the
/// `auth_middleware` and returns them as JSON.
///
/// # Example
/// ```
/// GET /auth/whoami
/// Response: { "sub": "user123", "iat": 1670000000, "exp": 1670003600 }
/// ```
async fn whoami(Extension(claims): Extension<Claims>) -> Json<Claims> {
    Json(claims)
}

/// Creates a router for authentication-related routes.
///
/// # Routes
/// - `POST /auth/login` → login handler
/// - `GET /auth/whoami` → returns the authenticated user's claims
pub fn auth_router() -> Router {
    Router::new()
        .route("/auth/login", post(login))
        .route("/auth/whoami", get(whoami))
}

/// Wraps a router with the `auth_middleware` to protect its routes.
///
/// # Usage
/// ```
/// let protected_router = protect_routes(some_router);
/// ```
pub fn protect_routes(router: Router) -> Router {
    router.layer(from_fn(auth_middleware))
}