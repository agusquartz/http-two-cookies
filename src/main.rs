mod auth;
mod photos;

use axum::{
    routing::get,
    Router,
};
use dotenvy::from_filename;
use tower_cookies::CookieManagerLayer;
use auth::router::{protect_routes};
use tower_http::cors::{CorsLayer};
use axum::http::{Method, header, HeaderName};
use axum::http::HeaderValue;
use axum_server::tls_rustls::RustlsConfig;
use std::net::SocketAddr;

async fn health() -> &'static str {
    "ok"
}

#[tokio::main]
async fn main() {
    
    // -------------------------------------------------------------------------
    // LOAD ENVIRONMENT VARIABLES
    // -------------------------------------------------------------------------
    let mut path = dirs::config_dir()
        .ok_or("Cannot find configuration directory").unwrap();

    path.push("http-two-cookies/.env");

    from_filename(&path)
        .ok()
        .expect("Failed to load environment variables from .env file");

    // -------------------------------------------------------------------------
    // TLS CONFIGURATION
    // -------------------------------------------------------------------------
    let tls_cert_path = std::env::var("TLS_CERT_PATH")
        .expect("TLS_CERT_PATH must be set");

    let tls_key_path = std::env::var("TLS_KEY_PATH")
        .expect("TLS_KEY_PATH must be set");

    let tls_config = RustlsConfig::from_pem_file(tls_cert_path, tls_key_path)
        .await
        .expect("Failed to load TLS certificates");


    // -------------------------------------------------------------------------
    // CORS CONFIGURATION
    // -------------------------------------------------------------------------
    let cors_origin = std::env::var("CORS_ALLOWED_ORIGIN")
        .expect("CORS_ALLOWED_ORIGIN must be set");

    let cors = CorsLayer::new()
        .allow_origin(cors_origin.parse::<HeaderValue>().unwrap())
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([
            header::CONTENT_TYPE,
            HeaderName::from_static("x-csrf-token"),
        ])
        .allow_credentials(true);


    // -------------------------------------------------------------------------
    // ROUTES
    // -------------------------------------------------------------------------
    let protected_photos = protect_routes(photos::photos_router());
    // let protected_auth = protect_routes(auth::router::auth_router());

    let app = Router::new()
        .route("/health", get(health))
        .merge(auth::router::auth_router())
        .merge(protected_photos)
        // .merge(protected_auth)
        .layer(CookieManagerLayer::new())
        .layer(cors);


    // -------------------------------------------------------------------------
    // START THE SERVER
    // -------------------------------------------------------------------------
    let host = std::env::var("SERVER_HOST")
        .expect("SERVER_HOST must be set");

    let port: u16 = std::env::var("SERVER_PORT")
        .expect("SERVER_PORT must be set")
        .parse()
        .expect("SERVER_PORT must be a valid number");

    let addr: SocketAddr = format!("{}:{}", host, port)
        .parse()
        .expect("Invalid server address");

    axum_server::bind_rustls(addr, tls_config)
        .serve(app.into_make_service())
        .await
    .unwrap();
}
