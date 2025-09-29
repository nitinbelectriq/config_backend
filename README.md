# Node Backend (Secure) - Migrated from PHP structure

This project is a starter Node.js + Express backend implementing the PHP endpoints you provided, with JWT authentication and several security improvements applied.

## Features added
- JWT authentication (issue and verify tokens)
- Secure password hashing with bcrypt
- Cryptographically secure PIN generation with crypto.randomBytes
- Use of AES-GCM for any symmetric encryption helpers (if needed)
- Helmet, CORS, and rate limiting
- Enforced HTTPS redirect when behind a proxy (checks X-Forwarded-Proto)
- Nodemailer setup for sending emails (with guidance on SPF/DMARC)
- Guidance and example DNS records (SPF/DMARC) in README
- No sensitive values logged; avoid storing secrets in memory longer than needed
- Input validation placeholders (recommend express-validator)

## How to run
1. Copy `.env.example` to `.env` and fill values.
2. Install dependencies: `npm install`
3. Start: `npm start`

## Endpoints (mapped from PHP)
- POST /auth/signup
- POST /auth/login
- POST /auth/verify
- POST /auth/request-reset
- POST /auth/validate-pin
- POST /auth/update-password
- POST /auth/generate-pin
- GET  /files/url

## SPF / DMARC guidance
Add the following DNS TXT records at your DNS provider (replace example domain):

Example SPF (allows specific mail servers and a 3rd party mailer):
`v=spf1 ip4:198.51.100.10 include:sendgrid.net -all`

Example DMARC (monitoring mode):
`v=DMARC1; p=none; rua=mailto:dmarc-rua@yourdomain.com; ruf=mailto:dmarc-ruf@yourdomain.com; pct=100; fo=1`

When moving to enforcement, change `p=none` to `p=quarantine` or `p=reject` after monitoring reports.

## Notes on mobile related security items (from your scan)
- Rooted device checks: those are implemented in the mobile app; backend should require device attestation or refuse requests from rooted devices if the app sends a validated flag.
- Cleartext traffic: serve backend over HTTPS (use TLS on server or via reverse proxy).
- Janus / APK signing: ensure CI signs APKs and verify signatures; backend can verify app integrity if the app supplies attestation.

