# S John Paul — Portfolio with login, host controls and live updates

Needs **Node 22.13+**. No npm packages to install.

## Run locally
```
cp .env.example .env      # then edit .env: set OWNER_PASSWORD
npm start                 # http://localhost:3000
```

## Host account
`OWNER_EMAIL` + `OWNER_PASSWORD` in `.env` (or your host's environment variables) create the single host account on start-up.
The password is stored only as a salted scrypt hash in `data/app.db`. It is never in the page, the repo or any API response.
To change it: edit `OWNER_PASSWORD` and restart. Anyone else who registers is a plain *visitor*.

## How it is enforced
- `/` serves the login page unless the request has a valid server-side session; the portfolio HTML is never sent to signed-out users.
- Sessions: random 256-bit token in an HttpOnly, SameSite=Strict cookie (Secure in production); only its hash is stored. Logout deletes it.
- All content writes (`/api/projects`, `/api/certs`) check the host role on the server; visitors get 403, anonymous users 401.
- Uploads: PNG/JPG/GIF/WebP (and PDF for certificates), max 3 MB, type decided from the file bytes, random file names, served only to signed-in users.
- Login/sign-up are rate-limited (10 attempts / 10 min / IP). Set `TRUST_PROXY=1` behind a proxy so the real IP is used.
- Changes are pushed to every open session with server-sent events.

## Deploy
Needs a Node host with a **persistent disk** (Render, Railway, Fly.io, a VPS). Static hosts (GitHub Pages, Netlify static) cannot run this.
Set `OWNER_EMAIL`, `OWNER_PASSWORD`, `NODE_ENV=production`, `TRUST_PROXY=1`, and `DATA_DIR` to the persistent disk path. Serve over HTTPS.

## Not included
Email verification and "forgot password" (need an email service). Anyone can create a visitor account with any email address.

## Edit content
Social links: `CFG` in `private/index.html`. First-run content: `seed.json` (only used while the database is empty).
