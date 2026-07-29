# 🔐 NabuAuth — Central Single Sign-On (SSO & OAuth2) Server

Central OAuth2 / OpenID Connect (OIDC) Single Sign-On (SSO) and Wallet Management server for the **Nabu Ecosystem** (`NabuDesk`, `NabuGen`, `NabuGate`, `NabuVoice`, `NabuBot`).

---

## 📌 Architecture & Features

- **OAuth2 / OIDC Identity Provider**: Authorize code grant with PKCE (`/oauth/authorize`, `/oauth/token`).
- **Unified Nabu Account**: Single identity across all Nabu products (`auth.nabuxai.com`).
- **Centralized Pre-paid Wallet**: Shared token balance & credits used across `NabuGate` LLMs, `NabuVoice` TTS, and `NabuGen`.
- **Ecosystem Apps**:
  - `NabuDesk` (`https://desk.nabuxai.com`)
  - `NabuGen` (`https://gen.nabuxai.com`)
  - `NabuGate` (`https://gate.nabuxai.com`)
  - `NabuVoice` (`https://voice.nabuxai.com`)

---

## 🚀 API & OAuth Endpoints

- `GET /oauth/authorize` — User login & authorization screen
- `POST /oauth/token` — Exchange authorization code for OAuth2 JWT Access Token
- `GET /api/v1/user` — Authenticated user profile & active scopes
- `GET /api/v1/wallet/balance` — Current wallet balance (cents / OMR)
- `POST /api/v1/wallet/topup` — Top up wallet via Thawani / OMPAY gateway
- `POST /api/v1/wallet/debit` — Internal ecosystem API token debit

---

## 🛠 Setup

```bash
composer install
cp .env.example .env
php artisan key:generate
php artisan migrate
php artisan serve --port=8099
```
