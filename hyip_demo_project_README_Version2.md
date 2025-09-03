# Safe Investment / Savings Platform (Demo)

This repository is a **safe** investment/savings demo — NOT a HYIP/ponzi.  
Features:
- Express + MySQL backend (JWT auth, bcrypt)
- Simple deposit & withdraw request flows (admin approval required)
- KYC upload placeholder
- Plain HTML front-end
- Docker compose file (MySQL + app) for local dev

## Quick start (development)
1. Copy `.env.example` to `.env` and fill values.
2. `docker-compose up -d` (optional — runs mysql)
3. `cd backend` then `npm install`
4. `node server.js` (or use `nodemon`)
5. Open `frontend/login.html` in browser and use demo flows.