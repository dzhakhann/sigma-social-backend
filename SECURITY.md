# Security — required actions

The Supabase `service_role` key was previously hardcoded in both the server
source and the mobile client, and it is in git history of both repos. That key
is an all-powerful admin credential that bypasses Row Level Security. It must be
treated as compromised and rotated. The code no longer contains it, but the
leaked key keeps working until you revoke it.

## 1. Rotate the Supabase key (do this first)

1. Open the Supabase dashboard → your project → **Project Settings → API**.
2. Under **Project API keys**, find `service_role` and **Reset / Roll** it
   (in newer projects: Settings → API Keys → rotate the secret key).
   - If your project only offers "Reset JWT secret", note that this rotates
     `anon` and `service_role` together and will invalidate existing JWTs.
3. Copy the **new** `service_role` key.

After rotation the old leaked key stops working — that's the goal.

## 2. Put the new key in env vars (never in code)

Local development — edit `.env` (already gitignored):

```
SUPABASE_KEY=<new-service-role-key>
SUPABASE_SERVICE_ROLE=<new-service-role-key>
```

Production (Render) — Dashboard → your service → **Environment** → add:

```
SUPABASE_KEY = <new-service-role-key>
```

The server now **refuses to start** if no key is present (`process.exit(1)`),
so set this env var **before** the next deploy or the service won't boot.

## 3. Database migration (run once in Supabase SQL editor)

```sql
-- recovery phrase support (stores only the sha256 hash)
alter table users add column if not exists recovery_hash text;

-- email no longer required for new accounts
alter table users alter column email drop not null;
```

## 4. Deploy

```
git add -A && git commit -m "security: remove hardcoded key, server-side uploads, bcrypt, recovery phrase"
git push           # Render auto-redeploys
```

## What changed in the code

- `service_role` key removed from `server.js` and from the Flutter client
  (`constants.dart`). The key now comes only from `process.env`.
- New `POST /api/upload` endpoint: the client sends bytes, the **server**
  writes to Supabase Storage. The client never holds the key. All client
  upload sites (posts, avatars, chat photo/video/voice, reels) were switched
  to this endpoint.
- Passwords are now hashed with **bcrypt** on register and password reset.
  Login transparently upgrades any old plaintext rows to bcrypt on first
  successful sign-in.
- Registration is username + password (no email/phone) and issues a 12-word
  recovery phrase; only its hash is stored.

## Hardening already applied

- JWT sessions (HS256). Login / register / recover return a `token`. Every
  mutating endpoint requires `Authorization: Bearer <token>` and derives the
  acting user from the token (`req.userId`) instead of trusting `user_id` in
  the request body — so you can no longer act on behalf of another user.
  Ownership is enforced on edit/delete of comments, stories and messages, and
  message senders must belong to the chat.
  - Requires a stable, strong `JWT_SECRET` in env (the server warns if it's the
    default). Changing it invalidates all existing tokens (users re-login).
- Rate limiting (`express-rate-limit`): `/api/auth/*` (40 / 15 min), stricter
  on `/api/auth/recover` (10 / 15 min) to slow recovery-phrase brute force,
  and `/api/upload` (100 / 15 min). `trust proxy` is set for correct client IPs
  behind Render.
- Passwords hashed with bcrypt; legacy plaintext rows upgraded on login.
- Uploads go through the server; size-capped at 30 MB (`UPLOAD_MAX_BYTES`).
- CORS origins read from `CORS_ORIGIN` env (comma-separated).

## Required env (production / Render)

```
SUPABASE_KEY   = <rotated service_role key>   # server won't start without it
JWT_SECRET     = <long random string>         # signs session tokens
CORS_ORIGIN    = https://your-app-origin      # optional, defaults to *
```

## Still worth doing later

- Purge the old key from git history (e.g. `git filter-repo`) — rotating makes
  it useless, but scrubbing history is cleaner.
- Authenticate the Socket.IO channel too. The REST write path is now secured,
  but the raw `send_message` socket event still rebroadcasts without a token
  (it doesn't persist to the DB, so it's real-time spoofing only).
- GET/read endpoints are still open; add `authRequired` to them if the data
  should be private.
