# ITBA P4 — Mobile Secure Quiz (Render-ready)

A phone-first, server-backed version of the 400-question P4 quiz.

## Features
- Mobile-first responsive UI with large touch targets and one-question-per-screen layout.
- 10/25/50/100/400 question modes.
- 10 and 100 modes use topic-balanced random selection.
- Negative marking: +1 correct, -0.125 wrong, 0 unanswered.
- Access request → admin approval → one-time setup code → passkey registration.
- After registration, sign-in requires the registered passkey on that device.
- Admin can approve, revoke, or reset registered devices.
- SQLite database stored in `DATA_DIR`; Render mounts this at `/var/data`.

## Deploy to Render — easiest method

### 1. Put this folder in a GitHub repository
Upload the contents of this folder (`package.json`, `server.js`, `public/`, `data/`, `render.yaml`, etc.) to a **private** GitHub repository.

### 2. Create the Render service
In Render, choose **New → Blueprint** and select the GitHub repository.

Render will read `render.yaml` and configure:
- Node 20
- `npm ci` build
- `npm start`
- HTTPS web service
- 1 GB persistent disk at `/var/data`
- generated session secret
- admin password supplied by you

The persistent disk is important because the SQLite database contains access approvals and passkey registrations.

### 3. Set the admin password
When Render asks for `ADMIN_PASSWORD`, enter a strong password. Do not commit it to GitHub.

`SESSION_SECRET` is generated automatically.

### 4. Deploy
After deployment, Render gives you an HTTPS address such as:
`https://itba-p4-mobile-secure-quiz.onrender.com`

The server automatically uses Render's external URL for WebAuthn when `BASE_URL` is not manually set.

### 5. Open the quiz
Users open the Render URL on their phones. They do not install Node.js or any app.

Admin page:
`https://YOUR-RENDER-URL/admin`

## Local test
1. Install Node.js 20+.
2. Run `npm install`.
3. Set `ADMIN_PASSWORD` and `SESSION_SECRET` in the environment.
4. Run `npm start`.
5. Open `http://localhost:3000`.

For real phone/passkey use, use the HTTPS Render deployment.

## Important security limitation
This provides server-side access control plus passkey/device registration. It does not provide DRM. An authorized user can still photograph, screenshot, or manually copy quiz content. Browser APIs cannot guarantee that the same physical person/device will never share content.
