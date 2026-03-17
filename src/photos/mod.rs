use axum::{
    extract::{Path, Extension},
    routing::get,
    Json, Router,
};
use crate::auth::jwt::Claims;

/// Lists all photos for the authenticated user.
///
/// This is a demo endpoint that returns placeholder photo names
/// including the username from the JWT claims.
///
/// # Arguments
/// * `claims` – JWT claims extracted from the request extensions.
///
/// # Returns
/// JSON array of photo names.
async fn list_photos(Extension(claims): Extension<Claims>) -> Json<Vec<String>> {
    Json(vec![
        format!("photo1 owned by {}", claims.sub),
        format!("photo2 owned by {}", claims.sub),
    ])
}

/// Retrieves a specific photo by ID for the authenticated user.
///
/// This is a demo endpoint that returns a placeholder string
/// including the photo ID and the username from the JWT claims.
///
/// # Arguments
/// * `id` – The photo ID extracted from the URL path.
/// * `claims` – JWT claims extracted from the request extensions.
///
/// # Returns
/// JSON string representing the photo information.
async fn get_photo(
    Path(id): Path<u64>,
    Extension(claims): Extension<Claims>,
) -> Json<String> {
    Json(format!("photo {} owned by {}", id, claims.sub))
}

/// Returns a router containing all photo-related routes.
///
/// # Routes
/// - `GET /photos` → List all photos for the authenticated user.
/// - `GET /photos/{id}` → Retrieve a specific photo by ID.
pub fn photos_router() -> Router {
    Router::new()
        .route("/photos", get(list_photos))
        .route("/photos/{id}", get(get_photo))
}