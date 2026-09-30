# ITBA P4 Mobile Secure Quiz — Free Render One-Day Edition

Mobile-first P4 quiz with access requests, admin approval, one-time setup codes, and passkey/device registration.

## What this version uses

- Render Free Node.js web service
- Render Free Postgres (1 GB; Render currently expires free Postgres after 30 days)
- No persistent disk
- HTTPS provided by Render
- WebAuthn/passkeys for device-bound access
- 400-question P4 bank
- Topic-balanced randomization for 10- and 100-question modes
- Negative marking: +1 correct, -0.125 wrong, 0 unanswered

## Deploy on Render — easiest method

1. Create a GitHub repository and upload the **contents of this folder** (not the ZIP itself).
2. In Render, choose **New → Blueprint** and connect the GitHub repository.
3. Render will read `render.yaml` and create:
   - a Free web service
   - a Free Postgres database
4. When prompted, set `ADMIN_PASSWORD` to a strong temporary admin password.
5. Deploy.
6. Open the generated `https://...onrender.com` URL.
7. Open `/admin` and log in with the admin password.

### Important

The Render Free web service can sleep after 15 minutes without traffic and can take about a minute to wake. For a one-day event, this is usually acceptable; have the first participant open the site a little before the quiz begins.

Free Render Postgres is persistent but currently expires after 30 days. That is fine for a one-day event. Delete the Render services/database afterward if you no longer need them.

## Access flow

1. Participant opens the quiz URL.
2. Participant requests access with name/email.
3. Admin approves the request.
4. Admin receives a one-time setup code and privately gives it to that participant.
5. Participant enters email + setup code and registers a passkey on their phone.
6. Future login requires the registered phone/passkey.

A forwarded URL alone does not grant access.

## Local testing

Requires Node.js 20+ and PostgreSQL. Set DATABASE_URL, SESSION_SECRET and ADMIN_PASSWORD, then run:

    npm ci
    npm start

For real passkeys, use an HTTPS origin (localhost is also allowed by WebAuthn browsers for development).
