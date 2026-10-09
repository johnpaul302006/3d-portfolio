# S John Paul — 3D Portfolio with Visitor Access & Host-Only Controls

An interactive 3D developer portfolio built with Node.js, SQLite, server-side sessions, and live SSE updates. Zero external npm dependencies.

Requirements: **Node 22.13+** (uses native `node:sqlite`).

---

## Quick Start

```bash
# 1. Create your local environment configuration
cp .env.example .env

# 2. Configure your environment variables in .env
# OWNER_EMAIL=your_email@example.com
# OWNER_PASSWORD=your_secure_host_password_here

# 3. Start the application
npm start
# Visit http://localhost:3000
```

To run the automated test suite:
```bash
npm test
```

---

## Authentication & Access Control

### 1. Instant Visitor Access
- When visitors open the portfolio, the login screen is displayed.
- Visitors can enter **any valid email address and any password**.
- No pre-registration, email verification, or stored database credentials are required.
- The server validates the non-empty fields and grants a valid server-side `visitor` session.
- **Visitor permissions**:
  - View all portfolio sections, 3D turntable, projects, skills, journey, certifications, and contact details.
  - Open project links and social media channels.
  - Log out back to the login screen.
  - **All administrative controls (Add/Remove/Edit projects and certificates) are completely hidden from visitors**.
  - Direct API write requests from visitors return `403 Forbidden`.

### 2. Host-Only Administrative Access
- The single portfolio host is identified strictly by matching the configured server-side environment variables:
  - `OWNER_EMAIL`
  - `OWNER_PASSWORD`
- **Strict Verification Rule**: Only when **both** the email and password match the configured host credentials exactly does the session receive the `host` role.
- If someone enters the host email with an incorrect password, they enter as a standard visitor with **zero** administrative privileges.
- **Host permissions**:
  - Add new projects and courses.
  - Remove or edit existing projects.
  - Add certificates (via file upload or URL) and remove certificates.
  - Changes are permanently saved to SQLite and broadcast in real time to all active sessions via Server-Sent Events (SSE).

### 3. Server-Side Security & Role Enforcement
- Sessions use random 256-bit cryptographically secure tokens stored in `HttpOnly`, `SameSite=Strict` cookies (`Secure` in production).
- Only the SHA-256 hash of the token is stored in SQLite alongside the server-determined role (`host` or `visitor`).
- `/api/me` returns the verified session role.
- Every content write (`/api/projects`, `/api/certs`) validates `s.role === 'host'`. Visitors receive `403 Forbidden`; unauthenticated requests receive `401 Unauthorized`.
- Arbitrary visitor passwords are **never stored** in the database.
- Login attempts are rate-limited (10 attempts / 10 min / IP).

---

## Cloud Deployment (Render, Railway, Fly.io, VPS)

Deploy the repository to any Node 22+ hosting platform:

1. Connect your GitHub repository: `https://github.com/johnpaul302006/3d-portfolio`.
2. Configure **Environment Variables** in the hosting dashboard:
   - `OWNER_EMAIL`: Your host email (e.g. `sjohnpaul638@gmail.com`)
   - `OWNER_PASSWORD`: Your secure host password (e.g. `Admin1234!`)
   - `NODE_VERSION`: `22` (or >= 22.13)
   - `NODE_ENV`: `production`
   - `TRUST_PROXY`: `1` (when running behind Render/Railway/nginx reverse proxy)
   - `DATA_DIR`: Path to a persistent disk (e.g. `/var/data` if using persistent volume)
3. Build Command: *(leave empty or `npm install`)*
4. Start Command: `node server.js`
