import os
import re
import sqlite3
import threading

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from . import db, llm
from .agents import run_agent
from .config import ROOT
from .gateway import LOCK, State
from .manifests import ALL_TOOLS, MANIFESTS
from .mockcorp import TOOL_SCHEMAS

app = FastAPI(title="DriftGuard")
STATIC = os.path.join(ROOT, "static")
app.mount("/static", StaticFiles(directory=STATIC), name="static")
COOKIE = "dg_session"
DOMAINS = ["suppliers", "documents", "purchasing", "finance", "hr", "comms", "delegation"]

WORKSPACES = db.load_workspaces()
for _ws in WORKSPACES.values():
    _ws.running = set()


def ws(uid):
    if uid not in WORKSPACES:
        WORKSPACES[uid] = State(uid)
        db.save_workspace(uid, WORKSPACES[uid])
    return WORKSPACES[uid]


def save(uid):
    with LOCK:
        db.save_workspace(uid, WORKSPACES[uid])


def uid_of(request: Request):
    uid = db.session_user(request.cookies.get(COOKIE))
    if not uid:
        raise HTTPException(401, "not logged in")
    return uid


def slug(name):
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:24] or "agent"


# ---------- pages ----------
@app.get("/")
def root(request: Request):
    return RedirectResponse("/app" if db.session_user(request.cookies.get(COOKIE)) else "/login")


@app.get("/login")
@app.get("/signup")
def auth_page():
    return FileResponse(os.path.join(STATIC, "auth.html"))


@app.get("/app")
def app_page(request: Request):
    if not db.session_user(request.cookies.get(COOKIE)):
        return RedirectResponse("/login")
    return FileResponse(os.path.join(STATIC, "app.html"))


# ---------- auth ----------
def _login_response(uid):
    r = JSONResponse({"ok": True})
    r.set_cookie(COOKIE, db.new_session(uid), httponly=True, samesite="lax", max_age=14 * 86400)
    return r


@app.post("/api/auth/signup")
async def signup(request: Request):
    b = await request.json()
    email, pw = str(b.get("email", "")).strip(), str(b.get("password", ""))
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        raise HTTPException(400, "Enter a valid email address")
    if len(pw) < 8:
        raise HTTPException(400, "Password must be at least 8 characters")
    if not str(b.get("name", "")).strip() or not str(b.get("org", "")).strip():
        raise HTTPException(400, "Name and organization are required")
    try:
        uid = db.create_user(email, b["name"], b["org"], pw)
    except sqlite3.IntegrityError:
        raise HTTPException(409, "An account with this email already exists")
    ws(uid)
    return _login_response(uid)


@app.post("/api/auth/login")
async def login(request: Request):
    b = await request.json()
    uid = db.check_login(str(b.get("email", "")), str(b.get("password", "")))
    if not uid:
        raise HTTPException(401, "Wrong email or password")
    return _login_response(uid)


@app.post("/api/auth/logout")
def logout(request: Request):
    db.end_session(request.cookies.get(COOKIE))
    r = JSONResponse({"ok": True})
    r.delete_cookie(COOKIE)
    return r


# ---------- workspace ----------
@app.get("/api/state")
def state(request: Request):
    uid = uid_of(request)
    snap = ws(uid).snapshot()
    snap["me"] = db.user(uid)
    snap["llm"] = {"available": llm.available(), "label": llm.label()}
    snap["templates"] = {k: {kk: v[kk] for kk in ("name", "purpose", "tools", "domains", "egress", "can_delegate")} for k, v in MANIFESTS.items()}
    snap["all_tools"], snap["all_domains"] = ALL_TOOLS, DOMAINS
    snap["settings"] = ws(uid).settings
    snap["canaries"] = sorted(getattr(ws(uid).company, "canaries", set()))
    return snap


@app.post("/api/agents")
async def create_agent(request: Request):
    uid = uid_of(request)
    b, s = await request.json(), ws(uid)
    name = str(b.get("name", "")).strip()
    if not name or not str(b.get("purpose", "")).strip():
        raise HTTPException(400, "Name and purpose are required")
    aid = slug(b.get("id") or name)
    if aid in s.agents:
        raise HTTPException(409, f"An agent with id '{aid}' already exists")
    me = db.user(uid)
    manifest = {"name": name, "purpose": b["purpose"].strip(), "owner": me["email"], "cohort": b.get("template") or aid,
                "tools": [t for t in b.get("tools", []) if t in ALL_TOOLS], "domains": [d for d in b.get("domains", []) if d in DOMAINS],
                "egress": sorted({e.strip().lower() for e in b.get("egress", []) if e.strip()} | {"mockcorp.internal"}),
                "can_delegate": [x for x in b.get("can_delegate", []) if x]}
    a = s.add_agent(aid, manifest)
    save(uid)
    return {"id": aid, "token": a.token}


@app.post("/api/agents/{aid}/rotate")
def rotate(aid: str, request: Request):
    uid = uid_of(request)
    if aid not in ws(uid).agents:
        raise HTTPException(404)
    tok = ws(uid).rotate_token(aid)
    save(uid)
    return {"id": aid, "token": tok}


@app.post("/api/agents/{aid}/release")
def release(aid: str, request: Request):
    uid = uid_of(request)
    if aid not in ws(uid).agents:
        raise HTTPException(404)
    r = ws(uid).release(aid)
    save(uid)
    return r


@app.post("/api/tasks")
async def run_task(request: Request):
    uid = uid_of(request)
    b, s = await request.json(), ws(uid)
    aid, task = b.get("agent"), str(b.get("task", "")).strip()
    if aid not in s.agents or not task:
        raise HTTPException(400, "Pick an agent and write a task")
    if not llm.available():
        raise HTTPException(400, "No LLM key configured on the server (.env)")
    if aid in s.running:
        raise HTTPException(409, "This agent is already working on a task")

    def work():
        s.running.add(aid)
        try:
            run_agent(s, aid, task, untrusted=bool(b.get("untrusted")))
        except Exception as e:  # surface LLM/provider errors in the activity log
            s.log.append(f"⚠ {aid}: {type(e).__name__}: {str(e)[:180]}")
        finally:
            s.running.discard(aid)
            save(uid)

    threading.Thread(target=work, daemon=True).start()
    return {"started": aid}


@app.post("/api/documents")
async def upload(request: Request):
    uid = uid_of(request)
    b = await request.json()
    name, text = os.path.basename(str(b.get("name", "")).strip()), str(b.get("text", ""))
    if not name or not text:
        raise HTTPException(400, "A file name and content are required")
    if len(text) > 200_000:
        raise HTTPException(400, "File too large (200 KB max)")
    folder = b.get("folder") if b.get("folder") in ("documents", "finance", "hr") else "documents"
    with LOCK:
        ws(uid).company.add_document(name, folder, text, canary=bool(b.get("canary")))
        ws(uid).log.append(f"⬆ {db.user(uid)['name']} uploaded {name} to {folder}")
    save(uid)
    return {"ok": True}


@app.post("/api/plugins")
async def plugin(request: Request):
    uid = uid_of(request)
    b = await request.json()
    if not str(b.get("name", "")).strip() or not str(b.get("source", "")).strip():
        raise HTTPException(400, "Name and source code are required")
    p = ws(uid).register_plugin(b["name"].strip(), str(b.get("vendor", "")), str(b.get("description", "")), b["source"])
    save(uid)
    return p


@app.post("/api/approval/{aid}/{decision}")
def approval(aid: int, decision: str, request: Request):
    uid = uid_of(request)
    r = ws(uid).approve(aid, decision in ("approve", "learn"), learn=decision == "learn", by=db.user(uid)["email"]) or {}
    save(uid)
    return r


@app.post("/api/settings")
async def settings(request: Request):
    uid = uid_of(request)
    b = await request.json()
    url = str(b.get("webhook", "")).strip()
    if url and not url.startswith(("http://", "https://")):
        raise HTTPException(400, "Webhook must be an http(s) URL")
    with LOCK:
        ws(uid).settings.update(sanitize=bool(b.get("sanitize")), webhook=url)
    save(uid)
    return ws(uid).settings


@app.post("/api/events/{eid}/explain")
def explain(eid: int, request: Request):
    uid = uid_of(request)
    s = ws(uid)
    ev = next((e for e in s.events if e["id"] == eid), None)
    if not ev:
        raise HTTPException(404)
    if not llm.available():
        raise HTTPException(400, "No LLM key configured on the server (.env)")
    a = s.agents.get(ev["agent"])
    facts = {"agent": ev["agent"], "role": a.manifest["purpose"] if a else "", "declared_tools": a.manifest["tools"] if a else [],
             "action": {"tool": ev["tool"], "args": ev["args"], "destination": ev.get("host")}, "risk_score": ev["score"],
             "decision": ev["decision"], "enforcement": ev["reason"], "signals": ev["signals"], "evidence_chain": ev.get("chain")}
    text = llm.complete([
        {"role": "system", "content": "You are a security analyst. Explain an AI-agent security alert to a busy SOC lead in plain English: "
                                      "3 short sentences (what the agent did, why it is suspicious, what was done), then one line starting "
                                      "'Recommended next step:'. Use only the facts given. No markdown headings."},
        {"role": "user", "content": str(facts)}])
    ev["ai_summary"] = text.strip()
    save(uid)
    return {"summary": ev["ai_summary"]}


@app.post("/api/changes")
async def new_change(request: Request):
    uid = uid_of(request)
    b, s = await request.json(), ws(uid)
    if b.get("agent") not in s.agents or not str(b.get("reason", "")).strip():
        raise HTTPException(400, "Pick an agent and give a reason")
    ch = s.request_change(b["agent"], [t for t in b.get("tools", []) if t in ALL_TOOLS], [d for d in b.get("domains", []) if d in DOMAINS],
                          [e.strip().lower() for e in b.get("egress", []) if e.strip()], b["reason"].strip())
    save(uid)
    return ch


@app.post("/api/changes/{cid}/approve")
def approve_change(cid: int, request: Request):
    uid = uid_of(request)
    r = ws(uid).approve_change(cid) or {}
    save(uid)
    return r


# ---------- public gateway API: what an agent (or anyone holding its token) calls ----------
def _agent_from_bearer(request: Request):
    tok = request.headers.get("authorization", "").removeprefix("Bearer ").strip()
    for uid, s in WORKSPACES.items():
        a = s.agent_by_token(tok)
        if a:
            return uid, s, a, tok
    raise HTTPException(401, "invalid agent token")


@app.get("/v1/tools")
def list_tools():
    return TOOL_SCHEMAS


@app.post("/v1/sessions")
async def open_session(request: Request):
    uid, s, a, _ = _agent_from_bearer(request)
    b = await request.json() if request.headers.get("content-length", "0") != "0" else {}
    sid = s.start_session(a.id, str(b.get("task", "")), untrusted=bool(b.get("untrusted")))
    save(uid)
    return {"session": sid}


@app.post("/v1/tools/{tool}")
async def call_tool(tool: str, request: Request):
    uid, s, a, tok = _agent_from_bearer(request)
    if tool not in ALL_TOOLS:
        raise HTTPException(404, "unknown tool")
    args = await request.json() if request.headers.get("content-length", "0") != "0" else {}
    client = request.headers.get("user-agent", "unknown") + " @" + (request.client.host if request.client else "?")
    with LOCK:
        out = s.call(tok, tool, args, request.headers.get("x-session"), client)
        ev = s.events[-1] if s.events else {}
    save(uid)
    return {"decision": ev.get("decision"), "risk_score": ev.get("score"), "reason": ev.get("reason"),
            "signals": ev.get("signals", []), "result": out if ev.get("decision") == "allowed" else None}
