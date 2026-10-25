import os
import threading

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from . import llm, scenarios
from .config import ROOT
from .gateway import STATE

app = FastAPI(title="DriftGuard")
STATIC = os.path.join(ROOT, "static")
app.mount("/static", StaticFiles(directory=STATIC), name="static")


@app.get("/")
def index():
    return FileResponse(os.path.join(STATIC, "index.html"))


@app.get("/api/state")
def state():
    snap = STATE.snapshot()
    snap["llm"] = {"available": llm.available(), "label": llm.label()}
    snap["scenarios"] = [{k: s.get(k) for k in ("id", "title", "desc", "expect", "color", "scripted")} for s in scenarios.SCENARIOS]
    snap["recorded"] = [s["id"] for s in scenarios.SCENARIOS if os.path.exists(scenarios._path(s["id"]))]
    return snap


@app.post("/api/scenario/{sid}")
def run_scenario(sid: str, mode: str = "live"):
    if sid not in scenarios.BY_ID:
        raise HTTPException(404)
    if STATE.running:
        raise HTTPException(409, "a scenario is already running")
    STATE.running = {"id": sid, "title": scenarios.BY_ID[sid]["title"], "mode": mode}
    threading.Thread(target=scenarios.run, args=(sid, mode), daemon=True).start()
    return {"started": sid}


@app.post("/api/reset")
def reset():
    if not STATE.running:
        STATE.reset()
    return {"ok": True}


@app.post("/api/approval/{aid}/{decision}")
def approval(aid: int, decision: str):
    return STATE.approve(aid, decision == "approve") or {}


@app.post("/api/change/{cid}/approve")
def change(cid: int):
    return STATE.approve_change(cid) or {}


@app.post("/api/agent/{agent_id}/release")
def release(agent_id: str):
    if agent_id not in STATE.agents:
        raise HTTPException(404)
    return STATE.release(agent_id)
