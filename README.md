# DriftGuard: identity drift detection for autonomous AI agents

Valid token, wrong behavior. Every agent tool call goes through a gateway that checks it against the agent's
declared role, its learned baseline and what it just read, then allows, holds, scopes down or quarantines.

## Run
```bash
pip install -r requirements.txt
python -m uvicorn app.main:app --port 8010     # open http://localhost:8010
```
Put one Groq key in `.env` (`GROQ_API_KEY=...`) for live LLM agents. Without a key, every scenario runs in Replay mode.
Gemini works too: `LLM_PROVIDER=gemini` + `GEMINI_API_KEY`.

## Use it
1. Sign up at `/signup`. Each account gets its own workspace (stored in `data/driftguard.db`).
2. **Agents** tab: register an agent from a role template or a custom role. Copy its token (shown once).
3. **Run a task**: a live LLM agent does the work. Tick "came from outside" for untrusted requests.
4. **Documents**: upload files. Agents read them during their work, including any hidden text.
5. **API**: any agent, or anyone holding a token, calls `POST /v1/tools/{tool}` with `Authorization: Bearer <token>`.
6. **Governance**: approve held actions, file and approve role changes, submit tool source code for a CodeGuard review.

`http_post` to `localhost`/`127.0.0.1` is really sent (run your own receiver to see it arrive); other external hosts are
sandboxed and logged under Outbound traffic.

## How it works
- `app/mockcorp.py`: fake company (suppliers, ERP, HR files, documents, mail, external sink). Nothing leaves the machine.
- `app/manifests.py`: declared role per agent + the normal history its baseline is learned from.
- `app/gateway.py`: IAM check → enrichment → detectors → risk score → enforcement (allow <40, hold 40–59, scope-down 60–79, quarantine ≥80).
- `app/detect.py`: role conformance, behavior baseline (with role-cohort cold start), injection provenance, exfiltration (source → sink),
  slow drift (CUSUM), delegation chain, token misuse.
- `app/agents.py`: real LLM agents (Groq/Gemini, OpenAI-compatible tool calling) whose only way to act is the gateway.
- `app/db.py`: accounts (PBKDF2-hashed passwords), login sessions, persisted workspaces.
- `app/main.py`: web app, auth, workspace API and the public gateway API (`/v1/...`).
- `vendor/codeguard`: our earlier CodeGuard project (injection detector + code scanner), reused for injection scoring and tool-registry scans.

Disclosure: built with Claude (AI coding assistant). CodeGuard is prior work by the same team.
