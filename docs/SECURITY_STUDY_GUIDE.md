# Security Study Guide: Authentication Process

This document provides a comprehensive overview of the security patterns and implementations used throughout the project's authentication lifecycle.

## 1. Core Cryptographic Primitives
The `better-auth` package employs modern cryptography choices to secure its core functions.
- **Password Hashing:** Uses `scrypt` from the `@noble/hashes` library (`scryptAsync`) as the default asynchronous hashing function for standard environments, applying a high memory and computation cost (`N=16384, r=16, p=1`). Salts are randomly generated using `crypto.getRandomValues`.
- **Symmetric Encryption & Signing:** Employs the `xchacha20poly1305` authenticated cipher from `@noble/ciphers` to symmetrically encrypt and decrypt data (like JWE cookies) and `HMAC-SHA256` for signing JWT tokens and generating message authentication codes.
- **Timing Attack Resistance:** Evaluates password hashes and tokens using a custom `constantTimeEqual` function to avoid early-exit timing vulnerabilities.

## 2. Cloudflare Workers Optimizations (`pieces/`)
For specific runtime constraints, optimized solutions have been developed.
- **CPU Time Mitigation:** Cloudflare Workers enforce strict CPU time limits that can cause timeouts (Error 1102) when using intensive algorithms like `scrypt`. The file `pieces/src/optimized-auth.ts` implements native **Web Crypto API (PBKDF2)** for password hashing, running iterations (100,000) using native extensions to drastically cut execution time.
- **Machine-to-Machine Auth:** Implements stateless/long-lived `signInMachine` and `createMachineToken` to accommodate headless authentication scenarios while offloading the standard session lifecycle.
- **Optimized SSO Integration:** The `pieces/src/optimized-sso.ts` module generates native OAuth2 endpoints and validates tokens without adding extra dependency bloat, catering specifically to Google and Microsoft Entra ID.

## 3. Route Security & Attack Mitigations
API routes handling authentication flows include targeted defenses against enumeration and timing attacks.
- **Email Enumeration Prevention:** In routes like `/sign-in/email` and `/request-password-reset`, the system actively avoids leaking whether an account exists. If an email is *not* found in the database, the server simulates the required operational cost—either by hashing a dummy password or executing a dummy token lookup—ensuring response times match those of valid inputs.
- **Origin Checking:** Validates the origin of incoming callbacks and utilizes Anti-CSRF (`formCsrfMiddleware`) middlewares for form-based actions.

## 4. Session and Token Management
State is securely managed using a hybrid database/cookie system.
- **Session Cache & Refresh:** Sessions are typically managed within the database but are accompanied by a chunked cache cookie strategy (JWT or encrypted JWE). This avoids excessive database reads while validating requests.
- **Freshness Evaluation:** Sensitive routes enforce a `freshSessionMiddleware` check. This prevents outdated, but still technically valid, sessions from authorizing critical endpoints like password resets unless the session was updated recently.
- **Granular Revocation:** Exposes API tools to explicitly revoke the current session (`revokeSession`), all sessions (`revokeSessions`), or all *other* sessions (`revokeOtherSessions`), granting granular control over active logins during security events.

## 5. Extensible Plugin Ecosystem
The authentication layer relies on plugins to support robust security requirements gracefully:
- **Core Integrations:** Modules for Bearer tokens, JWT verification, and API key management provide flexible validation.
- **Advanced Authentication Flow:** Out-of-the-box support for Passkeys (WebAuthn), Multi-Factor Authentication (Two-Factor/MFA), Email OTP, Magic Links, and CAPTCHA handling.
- **Threat Intelligence:** A plugin exists for integration with HaveIBeenPwned to protect against known compromised passwords.
