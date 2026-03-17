
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::{env, time::{SystemTime, UNIX_EPOCH}};
use once_cell::sync::Lazy;

/// Lazy-initialized JWT secret.
///
/// Reads the `JWT_SECRET` environment variable **once on first access** and stores
/// it in memory. This avoids hardcoding secrets and repeated environment lookups.
///
/// # Example
/// ```
/// let secret: &[u8] = jwt_secret();
/// ```
static JWT_SECRET: Lazy<Vec<u8>> = Lazy::new(|| {
    env::var("JWT_SECRET")
        .expect("JWT_SECRET environment variable must be set")
        .into_bytes()
});

/// Returns a reference to the JWT secret.
///
/// This function gives access to the secret as a byte slice for
/// signing and verifying tokens.
fn jwt_secret() -> &'static [u8] {
    &JWT_SECRET
}

/// Structure representing the payload (claims) of a JWT.
///
/// **Parts of a JWT:**
/// A JWT has three parts separated by dots (`.`):
/// 
/// 1. **Header** – metadata about the token, usually includes `alg` (algorithm) and `typ` (type).
///    Example:
///    ```json
///    {
///        "alg": "HS256",
///        "typ": "JWT"
///    }
///    ```
///
/// 2. **Payload** – the claims, which are statements about the user or token.
///    Example for a user with a role and permissions:
///    ```json
///    {
///        "sub": "alice@example.com",
///        "iat": 1670000000,
///        "exp": 1670003600,
///        "role": "admin",
///        "permissions": ["read:photos", "write:photos", "delete:photos"]
///    }
///    ```
///    - `sub` → the username or user ID
///    - `iat` → issued at timestamp
///    - `exp` → expiration timestamp
///    - `role` → the user's role
///    - `permissions` → list of allowed actions for this user
///
/// 3. **Signature** – a cryptographic signature created by combining the encoded header, 
///    encoded payload, and a secret key using the algorithm specified in the header.
///    Example:
///    ```
///    HMACSHA256(
///      base64UrlEncode(header) + "." + base64UrlEncode(payload),
///      secret
///    )
///    ```
///
/// Together, a JWT looks like:
/// `header.payload.signature`
///
/// Example token (not real):
/// `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhbGljZUBleGFtcGxlLmNvbSIsImlhdCI6MTY3MDAwMDAwMCwiZXhwIjoxNjcwMDAzNjAwLCJyb2xlIjoiYWRtaW4iLCJwZXJtaXNzaW9ucyI6WyJyZWFkOnBob3RvcyIsIndyaXRlOnBob3RvcyIsImRlbGV0ZTpwaG90b3MiXX0.Xu2F2fN6M7tK9xH9ZsPOp6K8VpzWmY4BfSjkkNq2gMQ`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Subject (usually a user identifier)
    pub sub: String,
    /// Issued at: UNIX timestamp when the token was created
    pub iat: usize,
    /// Expiration: UNIX timestamp when the token expires
    pub exp: usize,
}

/// Creates and signs a JWT token.
///
/// # Arguments
/// * `subject` – Identifier of the user (username, ID, etc.)
/// * `ttl_seconds` – Time-to-live of the token in seconds
///
/// # Returns
/// Signed JWT string if successful.
///
/// **How it works:**
/// 1. Get current time (`iat`) and calculate expiration (`exp`).
/// 2. Construct the payload (`Claims`).
/// 3. Use `jsonwebtoken` crate to encode header + payload + sign with `JWT_SECRET`.
///
/// # Example
/// ```
/// let token = create_jwt("user123", 3600)?;
/// ```
pub fn create_jwt(
    subject: &str,
    ttl_seconds: u64,
) -> Result<String, jsonwebtoken::errors::Error> {
    // Current UNIX timestamp
    let current_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Build the claims (payload)
    let jwt_claims = Claims {
        sub: subject.to_owned(),
        iat: current_timestamp as usize,
        exp: (current_timestamp + ttl_seconds) as usize,
    };

    // Encode the token with default header (alg: HS256, typ: JWT)
    encode(
        &Header::default(),
        &jwt_claims,
        &EncodingKey::from_secret(jwt_secret()),
    )
}

/// Verifies a JWT token and extracts its claims.
///
/// # Arguments
/// * `token` – JWT token string from the client
///
/// # Returns
/// Decoded `Claims` if the token is valid.
///
/// **How verification works:**
/// 1. Decode the token, split into header, payload, and signature.
/// 2. Verify the signature using `JWT_SECRET`.
/// 3. Validate standard claims (like `exp`) using `Validation::default()`.
/// 4. Return the payload (claims) if everything passes.
///
/// **Why it returns claims:**  
/// The claims contain the user identity and other information encoded in the token
/// (like username, role, permissions). Returning them allows the application
/// to know **who the request is from** and what actions they are authorized to perform.
pub fn verify_jwt(
    token: &str,
) -> Result<Claims, jsonwebtoken::errors::Error> {
    // Decode the token and verify signature
    let decoded_token = decode::<Claims>(
        token,
        &DecodingKey::from_secret(jwt_secret()),
        &Validation::default(),
    )?;

    // Return the claims
    Ok(decoded_token.claims)
}