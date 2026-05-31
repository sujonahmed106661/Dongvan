# Neroxa Combined Bot

## Features
- 🔑 2FA Manager — TOTP/OTP key management with QR code support
- 📬 Mail Box — Outlook/Hotmail OTP reader via DongVan API
- ⚙️ Admin Panel — Broadcast, Force Join channels, User stats

## Deploy to Railway (5 steps)
1. Extract this zip
2. Push all files to a **private** GitHub repository
3. Go to [railway.app](https://railway.app) → New Project → Deploy from GitHub repo
4. Select the repo — Railway detects `Procfile` automatically
5. Done! No environment variables needed — all config is in `bot.py`

## Default Force Join Channels
- @NeroxaOfficial
- @NeroxaMethod

## Admin ID: 8502686983

## Notes
- `totp_data.json` auto-created at runtime (gitignored)
- Restart policy: auto-restart on failure (up to 10 times)
