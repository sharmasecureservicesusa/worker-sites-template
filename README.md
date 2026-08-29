# Workers Club

Members-only rewrite of the Cloudflare Workers Sites template. The public Ferris “Hello World” page is gone. Every HTML section and every JSON route now requires a verified membership.

## Stack

- **Python / FastAPI** — the application backend and OpenAuth-compatible issuer
- **Dolt** — MySQL-compatible, versioned database (membership, sessions, OAuth artifacts, library)
- **OpenAuth-style OAuth 2.0** — authorization code + PKCE (S256), refresh tokens, RS256 access tokens, OIDC discovery, userinfo

An OpenAuth.js client can point at this issuer:

```js
import { createClient } from "@openauthjs/openauth/client";

const client = createClient({
  clientID: "workers-club",
  issuer: "http://127.0.0.1:8000",
});
```

Discovery lives at `/.well-known/openid-configuration` and `/.well-known/oauth-authorization-server`. JWKS is at `/.well-known/jwks.json`.

## Club sections (all gated)

| Path | Purpose |
| --- | --- |
| `/login` `/register` `/verify` `/forgot` `/reset` | Public auth only |
| `/dashboard` | Clubhouse |
| `/directory` | Member roster |
| `/library` | Member briefing notes |
| `/history` | Dolt commit log |
| `/profile` | Name and password |

Unauthenticated visits to those pages 303 to `/login`. Unauthenticated `/api/*` calls return 401.

## Run locally

Install [Dolt](https://github.com/dolthub/dolt/releases), Python 3.12+, then:

```bash
python3 -m venv .venv
.venv/bin/pip install -r backend/requirements-dev.txt
chmod +x scripts/dev.sh
./scripts/dev.sh
```

Open http://127.0.0.1:8000 — you will be sent to sign-in.

Local demo membership (debug seed):

- Email: `member@workers.club`
- Password: `MembersOnly!2026`

Copy `.env.example` to `.env` and change `SECRET_KEY` before any real deployment. Set `COOKIE_SECURE=true` behind HTTPS.

## Tests

```bash
.venv/bin/pytest backend
```

Tests boot an ephemeral Dolt SQL server, so `dolt` must be on `PATH`.

## Auth model

1. Register with email / password (scrypt). A 6-digit email code is required before sign-in.
2. Sign-in issues an HttpOnly `SameSite=Lax` session cookie stored hashed in Dolt.
3. Password reset issues a second one-time code and revokes existing sessions.
4. First-party OAuth client `workers-club` uses the code + PKCE flow. Access tokens are RS256 JWTs; refresh tokens are opaque and hashed in Dolt.
5. The membership middleware runs on every non-public path.

Writes call `CALL DOLT_COMMIT`, so `/history` is a real ledger, not a mock.

The original `workers-site` Worker and `wrangler.toml` remain in the tree as the previous static host. The live application is the Python process above.
