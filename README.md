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

## How it works
- `app/mockcorp.py`: fake company (suppliers, ERP, HR files, documents, mail, external sink). Nothing leaves the machine.
- `app/manifests.py`: declared role per agent + the normal history its baseline is learned from.
- `app/gateway.py`: IAM check → enrichment → detectors → risk score → enforcement (allow <40, hold 40–59, scope-down 60–79, quarantine ≥80).
- `app/detect.py`: role conformance, behavior baseline (with role-cohort cold start), injection provenance, exfiltration (source → sink),
  slow drift (CUSUM), delegation chain, token misuse.
- `app/agents.py`: real LLM agents (Groq/Gemini, OpenAI-compatible tool calling) whose only way to act is the gateway.
- `app/scenarios.py`: 8 scenarios. Live runs are recorded to `data/recordings/`; Replay re-sends them through the real gateway.
- `vendor/codeguard`: our earlier CodeGuard project (injection detector + code scanner), reused for injection scoring and tool-registry scans.

Disclosure: built with Claude (AI coding assistant). CodeGuard is prior work by the same team.
