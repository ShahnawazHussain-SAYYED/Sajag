# Sajag: scam and safety app (full version)

- `frontend/`  static site (HTML). Deploy on Netlify, Vercel or GitHub Pages.
- `backend/`   FastAPI server. Deploy on Render or Railway.
- Database: Supabase (Postgres). Run `backend/schema.sql` once.

Why a backend: the community database, the AI opinion and the live news extraction need secret keys and a shared database. Those cannot live safely inside a plain HTML file.

## Deploy in 4 steps (about 30 minutes)

### 1. Supabase (database)
1. Create a free project at supabase.com.
2. Open SQL Editor, paste all of `backend/schema.sql`, press Run.
3. Project Settings, API: copy the **Project URL** and the **service_role** key. Keep the service_role key secret.

### 2. Gemini (AI, free tier)
1. Go to aistudio.google.com, sign in with a Google account, click **Get API key**, then **Create API key**.
2. The model is set by `GEMINI_MODEL` (default `gemini-3.5-flash`). Google renames and retires models often, so open the AI Studio model list and use a current model that shows a free tier.
3. Free tier limits are small (roughly 10 requests per minute and a few hundred per day, and Google changes them). Your AI Studio dashboard shows the real numbers.
4. Free tier data may be used by Google to improve its products. Users paste their messages into the AI opinion feature, so add a privacy note, or enable billing (the paid tier does not use your data that way).
5. To use Claude instead, set `AI_PROVIDER=anthropic`, add `ANTHROPIC_API_KEY`, and uncomment `anthropic` in `requirements.txt`.

### 3. Backend on Render
1. Push this whole folder to a GitHub repo.
2. On render.com: New, Blueprint (it reads `render.yaml`), pick your repo.
3. Fill the environment variables: `SUPABASE_URL`, `SUPABASE_SERVICE_KEY`, `GEMINI_API_KEY`, `ALLOWED_ORIGIN` (your frontend address; use `*` only for the first test).
4. After deploy, open `https://YOUR-API.onrender.com/health`. It must show `{"ok":true}`.
   Note: the free Render plan sleeps when idle, so the first request can take about 30 seconds.

### 4. Frontend on Netlify (or Vercel / GitHub Pages)
1. Edit `frontend/config.js` and set `window.SAJAG_API` to your Render address.
2. Netlify: Add new site, Deploy manually, drag the `frontend` folder in.
3. Put the Netlify address into `ALLOWED_ORIGIN` on Render (no trailing slash) and redeploy.
4. Open the site on your phone. Browsers ask for location permission on https sites, so real GPS works here.

## Run locally
```
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # fill it, then: export $(cat .env | xargs)
uvicorn main:app --reload
```
Open `frontend/index.html` with any static server, for example `python -m http.server 5500` inside `frontend/`.
Set `ALLOWED_ORIGIN=http://localhost:5500` while testing.

## Before you go public
- Limits and costs: every AI opinion and every new news search calls the AI. News results are cached for 6 hours per place. The free Gemini tier can run out quickly if many people use the app, and then users see "try again in a minute". Enable billing and set a budget cap when you grow.
- Abuse: anyone can submit a report. Add moderation before promoting the app widely. Reports show as "reported by N users", never as "this is a scam".
- Privacy: crime reports store only an approximate point (about 1 km) and an anonymous browser id. Add a privacy policy page.
- News source: live news uses the free GDELT API, which has rate limits and only headlines. It is real news but not complete crime statistics.
- Safety: this app helps, it does not replace the police. For emergencies call your local emergency number.
