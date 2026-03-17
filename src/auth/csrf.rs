use rand::{distributions::Alphanumeric, Rng};
use once_cell::sync::Lazy;
use std::env;

/// Length of the CSRF token in bytes.
///
/// Loaded once from the `CSRF_TOKEN_BYTES` environment variable.
static CSRF_TOKEN_BYTES: Lazy<usize> = Lazy::new(|| {
    env::var("CSRF_TOKEN_BYTES")
        .expect("CSRF_TOKEN_BYTES must be set")
        .parse()
        .expect("CSRF_TOKEN_BYTES must be a valid number")
});

/// Generates a random CSRF token.
///
/// **CSRF (Cross-Site Request Forgery) tokens** are used to prevent
/// unauthorized actions performed on behalf of a logged-in user.
///
/// # Returns
/// A random alphanumeric string whose length is defined by
/// the `CSRF_TOKEN_BYTES` environment variable.
///
/// # Example
/// ```
/// let token = generate_csrf();
/// println!("CSRF token: {}", token);
/// ```
pub fn generate_csrf() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(*CSRF_TOKEN_BYTES)
        .map(char::from)
        .collect()
}