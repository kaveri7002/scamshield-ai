# ScamShield AI

ScamShield is a scam-message and suspicious-URL analysis prototype. The frontend is a static Vite app, the API is an Express service, and scan summaries are stored in MongoDB Atlas.

The analyzer uses transparent, local rules; it does not call an AI provider or a live threat-intelligence service. URL results are indicators only and are not proof that a site is safe or malicious.

## Requirements

- Node.js 20 or newer
- npm
- A MongoDB Atlas cluster (or another MongoDB connection string)

## Run locally

1. In `backend`, copy `.env.example` to `.env` and replace `MONGODB_URI` with your Atlas connection string. Add `http://localhost:5173` to `CLIENT_ORIGINS`.
2. Install and start the API:

   ```powershell
   cd backend
   npm install
   npm run dev
   ```

3. In another terminal, from the project root, install and run the frontend:

   ```powershell
   npm install
   npm run dev
   ```

4. Open the Vite URL shown in the terminal (normally `http://localhost:5173`). Check API connectivity at `http://localhost:8080/api/health`.

To run the rule-engine tests: `cd backend; npm test`. To create a production frontend build: run `npm run build` from the project root.

## Deploy MongoDB Atlas

1. Create an Atlas project and cluster.
2. Create a database user with a strong password. Use the cluster's **Connect → Drivers** connection string and replace its placeholders.
3. In **Network Access**, allow the Railway service to connect. For a hackathon prototype, Atlas `0.0.0.0/0` is easiest; use strong database credentials and tighten access when practical.
4. The application creates its `scans` collection and indexes when the first scan is recorded.

Never put the MongoDB connection string in the frontend or commit `.env` files.

## Deploy the API to Railway

1. Create a Railway project and deploy this repository from GitHub.
2. Set the service's **Root Directory** to `/backend` so Railway installs `backend/package.json` and runs its `npm start` command.
3. Add Railway variables:
   - `MONGODB_URI`: the Atlas connection string
   - `CLIENT_ORIGINS`: your exact Vercel production origin, for example `https://scamshield-ai.vercel.app` (comma-separate additional trusted origins)
   - `NODE_ENV`: `production`
4. Railway provides `PORT` automatically. Wait for deployment, then check `https://<your-railway-domain>/api/health`. It should report `"status":"ok"` and `"database":"connected"`.

## Deploy the frontend to Vercel

1. Import the repository in Vercel. Keep the **Root Directory** at the repository root.
2. Vercel detects Vite and uses `npm run build` with `dist` as the output directory.
3. Set the project environment variable `VITE_API_URL` to the Railway service origin, for example `https://scamshield-api.up.railway.app` (no trailing slash).
4. Redeploy after setting the variable. Add the resulting Vercel origin to Railway's `CLIENT_ORIGINS` and redeploy the API.

For a Vercel preview URL, add that exact origin to `CLIENT_ORIGINS`, or use the production deployment for API testing.

## API

All scan and history requests require the `X-Client-Id` header, which the frontend creates and keeps in this browser's local storage.

- `GET /api/health` — service/database status
- `POST /api/analyze/message` — JSON `{ "message": "..." }`
- `POST /api/analyze/url` — JSON `{ "url": "https://..." }`
- `GET /api/history` — this browser's latest 100 scan summaries
- `DELETE /api/history` — clear this browser's history

The database stores only the input type, risk score, risk level, threat category, timestamp, and a random browser identifier. It does **not** store the submitted message or URL. There is no user account system; the browser identifier scopes history for this prototype and is not an authentication mechanism.

## Limitations

- Analysis is heuristic and can miss scams or flag legitimate messages.
- URL checks inspect the submitted URL string only. They do not visit the destination, check certificates, or query a threat-intelligence feed.
- The “Explain Simply” feature uses a built-in explanation rather than a generative AI model.
