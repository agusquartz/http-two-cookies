# http-two-cookies
Minimal Rust HTTP server base implementing JWT + CSRF authentication using two cookies with Axum and Tokio. This project is intended as a starter template for building secure web APIs in Rust.

## Features

- JWT authentication stored in an HttpOnly cookie
- CSRF protection with a separate cookie (accessible by JavaScript)
- Middleware for automatic JWT + CSRF verification
- Example protected routes for testing authentication
- TLS support using Rustls
- CORS configuration with allowed origins, methods, and headers
- Environment-based configuration for flexible deployment

## Architecture
The project is organized as follows:
```
src/
 ├─ main.rs
 ├─ auth/
 │   ├─ handlers.rs
 │   ├─ jwt.rs
 │   ├─ csrf.rs
 │   ├─ middleware.rs
 │   └─ router.rs
 └─ photos/
     └─ mod.rs
```

- main.rs – Initializes environment variables, TLS, CORS, middleware, and routes.
- auth/jwt.rs – JWT creation and verification using a secret loaded from .env.
- auth/csrf.rs – Generates random CSRF tokens.
- auth/middleware.rs – Middleware enforcing JWT + CSRF validation on protected routes.
- auth/handlers.rs – Login handler that issues JWT + CSRF cookies.
- auth/router.rs – Auth routes (/auth/login, /auth/whoami) and route protection.
- photos/mod.rs – Example protected endpoints returning placeholder photo data.

## Environment Configuration
Create a .env file inside your OS config directory:
- Linux: ~/.config/http-two-cookies/.env
- macOS: ~/Library/Application Support/http-two-cookies/.env
- Windows: C:\Users\<User>\AppData\Roaming\http-two-cookies\\.env

Example .env:
```
# ---------------------------------------------------------------------
# AUTHENTICATION
# ---------------------------------------------------------------------

# Secret key used to sign and verify JWT tokens
JWT_SECRET=your_long_random_jwt_secret_here

# Default JWT lifetime in seconds (e.g., 1 hour)
JWT_TTL_SECONDS=3600

# ---------------------------------------------------------------------
# SERVER
# ---------------------------------------------------------------------

# HTTP server bind address
SERVER_HOST=127.0.0.1
SERVER_PORT=3000

# ---------------------------------------------------------------------
# TLS CONFIGURATION
# ---------------------------------------------------------------------

# TLS certificate and private key paths
TLS_CERT_PATH=/path/to/cert.pem
TLS_KEY_PATH=/path/to/key.pem

# ---------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------

# Allowed frontend origin
CORS_ALLOWED_ORIGIN=https://127.0.0.1:5500

# ---------------------------------------------------------------------
# SECURITY
# ---------------------------------------------------------------------

# CSRF token length in bytes
CSRF_TOKEN_BYTES=32
```

## Getting Started
### 1. Clone the repository
    ```bash
    git clone https://github.com/agusquartz/http-two-cookies.git
    cd http-two-cookies
    ```

### 2. Configure environment variables

    Follow the instructions above and create a .env file with your JWT secret, TLS certificates, server host/port, and allowed CORS origin.

### 3. Run the server
    ```bash
    cargo run
    ```
    The server will start on the host and port specified in .env using TLS.

## Routes
### Public
- GET /health – Returns "ok"
### Auth
- POST /auth/login – Logs in a user and sets the jwt and csrf cookies
    - `jwt` cookie → HttpOnly, Secure, SameSite=None
    - `csrf` cookie → Secure, SameSite=None (accessible by JS)

    Request example:
    ```http
    POST /auth/login
    Content-Type: application/json
    {
    "username": "user",
    "password": "password"
    }
    ```

    Response:
    ```JSON
    {}
    ```
    Note: In production, the CSRF token is sent via cookie, not JSON.
- GET /auth/whoami – Returns JWT claims for authenticated users

### Protected Example
- GET /photos – Returns placeholder photos for the logged-in user
- GET /photos/{id} – Returns a specific placeholder photo

All protected routes require valid JWT + CSRF tokens.

## Security Notes
- JWT Secret should never be hardcoded; load it from .env or a secret manager.
- JWT cookie is HttpOnly and Secure.
- CSRF token is exposed to the client for validation in state-changing requests.
- Middleware enforces JWT + CSRF validation using constant-time comparisons to prevent timing attacks.
- CORS configuration must match your frontend origin.

## Dependencies
- Axum – Web framework
- Tokio – Async runtime
- Tower HTTP – CORS and middleware utilities
- Tower Cookies – Cookie management
- jsonwebtoken – JWT handling
- rand – CSRF token generation
- OnceCell – Lazy initialization of JWT secret
- dotenvy – Load environment variables

## License
MIT