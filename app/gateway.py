"""Agent gateway: every tool call passes through here. IAM check, enrichment, detection, risk, enforcement.
One State per workspace (user account); it is persisted to SQLite after every change."""
import copy
import os
import secrets
import sys
import threading
import time

import httpx

from . import detect as D
from .config import ROOT
from .manifests import ALL_TOOLS
from .mockcorp import TOOL_META, Company, host_of, is_internal

sys.path.insert(0, os.path.join(ROOT, "vendor"))
from codeguard import engine as cg_engine, injection, textclf  # noqa: E402

LOCK = threading.RLock()
RUNTIME_CLIENT = "driftguard-runtime/1.0"


def inj_score(text):
    """CodeGuard's AI-instruction detector: phrase rules + learned classifier, max over both."""
    text = str(text or "")
    hits = [w for _, w, _ in injection.scan_injection(text, "markdown")]
    return max([textclf.score(text)] + hits)


def level_for(score):
    return "quarantine" if score >= 80 else "scope_down" if score >= 60 else "hold" if score >= 40 else "allow"


def new_token():
    return "dg_" + secrets.token_urlsafe(24)


class Agent:
    def __init__(self, aid, manifest):
        self.id, self.manifest = aid, {**copy.deepcopy(manifest), "version": 1}
        self.token = new_token()
        self.scopes = list(ALL_TOOLS)  # broad IAM scopes, like most real deployments
        self.client = None             # pinned on first use
        self.status, self.risk, self.cusum, self.last_tool, self.note = "healthy", 0.0, 0, None, ""
        self.revoked, self.declared_tools = set(), set()
        self.baseline = D.Baseline()
        self.risk_history = []
        self.created = time.time()

    def view(self):
        m = self.manifest
        return {"id": self.id, "name": m["name"], "purpose": m["purpose"], "owner": m.get("owner", ""), "version": m["version"],
                "cohort": m.get("cohort", "custom"), "tools": m["tools"], "domains": m["domains"], "egress": m["egress"],
                "can_delegate": m.get("can_delegate", []), "status": self.status, "risk": round(self.risk),
                "revoked": sorted(self.revoked), "cold_start": self.baseline.n < D.COLD_START_MIN,
                "baseline_n": self.baseline.n, "cusum": self.cusum, "note": self.note, "client": self.client,
                "token": self.token[:7] + "…" + self.token[-4:]}


class Session:
    def __init__(self, sid, agent, task, parent_agent=None):
        self.id, self.agent, self.task, self.parent_agent = sid, agent, task, parent_agent
        self.steps, self.taint, self.sensitive_reads = 0, None, []


class State:
    def __init__(self, uid):
        self.uid = uid
        self.company = Company()
        self.agents, self.cohorts, self.sessions = {}, {}, {}
        self.events, self.approvals, self.changes, self.plugins, self.log = [], [], [], [], []
        self.running = set()
        self.n = 0
        self.t0 = time.time()

    def next_id(self):
        self.n += 1
        return self.n

    def cohort(self, name):
        return self.cohorts.setdefault(name, D.Baseline())

    # ---------- agents ----------
    def add_agent(self, aid, manifest):
        with LOCK:
            a = Agent(aid, manifest)
            self.agents[aid] = a
            self.log.append(f"＋ Agent {manifest['name']} registered (role v1)")
            return a

    def rotate_token(self, aid):
        with LOCK:
            a = self.agents[aid]
            a.token, a.client = new_token(), None
            return a.token

    def register_plugin(self, name, vendor, description, source):
        with LOCK:
            r = cg_engine.analyze(source)
            p = {"name": name, "vendor": vendor, "description": description, "verdict": r["verdict"], "risk": r["risk_score"],
                 "categories": r["categories"], "reason": r.get("reason", "")}
            self.plugins.append(p)
            return p

    # ---------- sessions ----------
    def start_session(self, agent_id, task, parent_session=None, untrusted=False):
        with LOCK:
            sid = f"s{self.next_id()}"
            parent = self.sessions.get(parent_session)
            s = Session(sid, agent_id, task, parent.agent if parent else None)
            score = inj_score(task) if (untrusted or parent) else 0.0
            if score >= 0.5:
                s.taint = {"source": "incoming message" if not parent else f"task from {parent.agent}", "score": score,
                           "step": 0, "via": parent.agent if parent else None}
            elif parent and parent.taint:
                s.taint = {**parent.taint, "step": 0, "via": parent.agent}
            self.sessions[sid] = s
            return sid

    # ---------- the gateway call ----------
    def call(self, token, tool, args, session_id=None, client=RUNTIME_CLIENT):
        with LOCK:
            agent = self.agent_by_token(token)
            if agent is None:
                return "401 invalid token"
            if agent.client is None:
                agent.client = client
            sess = self.sessions.get(session_id)
            meta = TOOL_META.get(tool, {"domain": "unknown"})
            ev = {"id": self.next_id(), "t": round(time.time() - self.t0, 1), "ts": time.time(), "agent": agent.id, "tool": tool,
                  "args": {k: (str(v)[:120]) for k, v in (args or {}).items()}, "domain": meta["domain"],
                  "sensitivity": meta.get("sensitivity", "low"), "host": host_of(tool, args), "client": client,
                  "session": session_id, "parent": sess.parent_agent if sess else None,
                  "iam": "pass" if tool in agent.scopes else "fail", "signals": [], "chain": []}
            if tool == "read_document":
                folder = self.company.doc_folder((args or {}).get("name"))
                ev["domain"] = folder
                ev["sensitivity"] = {"finance": "medium", "hr": "high"}.get(folder, "low")
            caps = self._caps(ev, agent)

            if ev["iam"] == "fail":
                return self._finish(agent, sess, ev, "blocked", "IAM: tool not in token scopes", 0)
            if agent.status == "quarantined":
                return self._finish(agent, sess, ev, "blocked", "Token suspended: agent is quarantined", agent.risk)
            hit = [c for c in caps if c in agent.revoked]
            if hit:
                return self._finish(agent, sess, ev, "blocked", f"Capability revoked: {', '.join(hit)}", agent.risk)

            # ---- detection ----
            s = D.conformance(agent, ev) + D.baseline(agent, ev, self.cohort(agent.manifest.get("cohort", agent.id)))
            s += D.arguments(agent, tool, args) + D.burst(agent, ev["ts"])
            deviation = sum(x["points"] for x in s)
            s += D.canary(self.company, ev)
            s += D.provenance(sess, deviation)
            s += D.exfiltration(sess, ev)
            s += D.drift(agent, deviation)
            s += D.delegation(sess, self.agents)
            s += D.token_context(agent, sess, client)
            if tool == "delegate" and inj_score((args or {}).get("task", "")) >= 0.5:
                s.append(D.sig("Injection provenance", 20, "Delegated task carries AI-targeted instructions"))
            ev["signals"] = s
            score = min(100, sum(x["points"] for x in s))
            level = level_for(score)
            ev["chain"] = self._chain(sess, ev)

            if level == "allow":
                result = self._execute(agent, sess, ev, tool, args)
                if score < 25:
                    self._learn(agent, ev, args)
                self._finish(agent, sess, ev, "allowed", "", min(100, sum(x["points"] for x in ev["signals"])))
                return result
            if level == "hold":
                self.approvals.append({"id": len(self.approvals) + 1, "event": ev["id"], "agent": agent.id, "tool": tool,
                                       "args": args, "session": session_id, "score": score, "status": "pending"})
                return self._finish(agent, sess, ev, "held", "Held for human approval", score)
            if level == "scope_down":
                revoke = self._revocations(agent, ev)
                agent.revoked.update(revoke)
                return self._finish(agent, sess, ev, "blocked", f"Scoped down: revoked {', '.join(revoke)}; other work continues", score)
            agent.status = "quarantined"
            return self._finish(agent, sess, ev, "quarantined", "Agent quarantined: token suspended, owner notified", score)

    def agent_by_token(self, token):
        return next((a for a in self.agents.values() if a.token == token), None)

    def _caps(self, ev, agent):
        caps = [f"tool:{ev['tool']}", f"domain:{ev['domain']}"]
        if ev.get("host") and not is_internal(ev["host"]) and not D.host_allowed(ev["host"], agent.manifest["egress"]):
            caps.append("egress:unlisted")
        if ev["tool"] == "delegate":
            caps.append(f"delegate:{ev['args'].get('agent')}")
        return caps

    def _revocations(self, agent, ev):
        m, out = agent.manifest, []
        if ev["domain"] not in m["domains"] and ev["domain"] not in ("egress", "delegation"):
            out.append(f"domain:{ev['domain']}")
        if ev.get("host") and not is_internal(ev["host"]) and not D.host_allowed(ev["host"], m["egress"]):
            out.append("egress:unlisted")
        if ev["tool"] == "delegate":
            out.append(f"delegate:{ev['args'].get('agent')}")
        return out or [f"tool:{ev['tool']}"]

    def _execute(self, agent, sess, ev, tool, args):
        result = self.company.execute(tool, args)
        if tool == "read_document":
            sc = inj_score(result)
            ev["injection_score"] = round(sc, 2)
            if sc >= 0.5 and sess:
                sess.taint = {"source": args.get("name"), "score": sc, "step": sess.steps, "via": None}
                ev["signals"].append(D.sig("Injection provenance", 10,
                                           f"Untrusted content contains AI-targeted instructions (score {sc:.2f}); session tainted"))
            if sc >= 0.5 and self.settings.get("sanitize"):
                result, removed = self._sanitize(result)
                if removed:
                    ev["sanitized"] = removed
                    ev["signals"].append(D.sig("Content sanitized", 0, f"Removed {removed} hidden instruction line(s) before the agent saw them"))
            if ev["domain"] in ("finance", "hr") and sess:
                sess.sensitive_reads.append(args.get("name"))
        if tool == "read_hr_file" and sess:
            sess.sensitive_reads.append(args.get("name"))
        ev["result"] = str(result)[:160]
        return result

    def _learn(self, agent, ev, args=None):
        agent.baseline.learn(agent.last_tool, ev["tool"], ev.get("host"), args)
        self.cohort(agent.manifest.get("cohort", agent.id)).learn(agent.last_tool, ev["tool"], ev.get("host"), args)

    @property
    def settings(self):
        return self.__dict__.setdefault("_settings", {"sanitize": True, "webhook": ""})

    def _sanitize(self, text):
        """Remove only the lines carrying AI-targeted instructions, so the agent still gets the real content."""
        lines = text.split("\n")
        bad = {ln - 1 for ln, _, _ in injection.scan_injection(text, "markdown")}
        bad |= {i for i, l in enumerate(lines) if len(l.split()) >= 6 and textclf.score(l) >= 0.5}
        if not bad:
            return text, 0
        kept = [l for i, l in enumerate(lines) if i not in bad]
        kept.append(f"[DriftGuard removed {len(bad)} line(s) of hidden AI-targeted instructions from this document]")
        return "\n".join(kept), len(bad)

    def _alert(self, ev):
        url = self.settings.get("webhook")
        if not url or not url.startswith(("http://", "https://")):
            return
        text = (f"DriftGuard {ev['decision'].upper()}: agent `{ev['agent']}` → `{ev['tool']}` (risk {ev['score']}). {ev['reason']}\n"
                + "\n".join(f"+{s['points']} {s['layer']}: {s['detail']}" for s in ev["signals"]))
        payload = {"text": text, "event": {k: ev.get(k) for k in ("id", "agent", "tool", "args", "score", "decision", "reason", "signals", "chain")}}

        def send():
            try:
                httpx.post(url, json=payload, timeout=5)
            except httpx.HTTPError:
                pass
        threading.Thread(target=send, daemon=True).start()

    def _chain(self, sess, ev):
        steps = []
        if sess and sess.taint:
            steps.append({"role": "source", "label": f"{sess.taint['source']} (injection {sess.taint['score']:.2f})"})
        if sess:
            steps += [{"role": "via", "label": f"read {r}"} for r in sess.sensitive_reads]
        if steps:
            target = ev.get("host") or ev["args"].get("name") or ev["args"].get("agent") or ev["domain"]
            steps.append({"role": "sink", "label": f"{ev['tool']} → {target}"})
        return steps

    def _finish(self, agent, sess, ev, decision, reason, score):
        ev.update(decision=decision, reason=reason, score=int(score))
        if not ev["chain"] and score >= 40:
            ev["chain"] = self._chain(sess, ev)
        if sess:
            sess.steps += 1
        agent.last_tool = ev["tool"]
        agent.risk = max(agent.risk * 0.85, float(score))
        agent.risk_history.append([ev["t"], round(agent.risk)])
        if agent.status != "quarantined":
            agent.status = "restricted" if agent.revoked else "watching" if agent.risk >= 25 else "healthy"
        # risk flows back up the chain: whoever delegated a task that turned bad is suspect too
        if sess and sess.parent_agent and score >= 60 and sess.parent_agent in self.agents:
            p = self.agents[sess.parent_agent]
            p.risk = max(p.risk, score * 0.8)
            p.revoked.add(f"delegate:{agent.id}")
            p.note = f"Delegated task led {agent.manifest['name']} to a {decision} action"
            p.risk_history.append([ev["t"], round(p.risk)])
            if p.status != "quarantined":
                p.status = "restricted"
        self.events.append(ev)
        if score >= 60:
            self._alert(ev)
        if len(self.events) > 2000:
            self.events = self.events[-2000:]
        if decision == "allowed":
            return ev
        return f"{decision.upper()} by security policy: {reason}. Do not retry this action; continue with your remaining in-role work."

    # ---------- human actions ----------
    def approve(self, aid, ok, learn=False, by=""):
        with LOCK:
            ap = next((a for a in self.approvals if a["id"] == aid), None)
            if not ap or ap["status"] != "pending":
                return None
            ap["status"] = "approved" if ok else "denied"
            if ok:
                ap["result"] = str(self.company.execute(ap["tool"], ap["args"]))[:160]
            if ok and learn and ap["agent"] in self.agents:
                # the human's decision becomes part of the role: the same action will not alert again
                ev = next((e for e in self.events if e["id"] == ap["event"]), {})
                m = self.agents[ap["agent"]].manifest
                domain = ev.get("domain")
                host = ev.get("host")
                ch = self.request_change(ap["agent"], [ap["tool"]] if ap["tool"] not in m["tools"] else [],
                                         [domain] if domain and domain not in m["domains"] and domain not in ("egress", "delegation") else [],
                                         [host] if host and not is_internal(host) and not D.host_allowed(host, m["egress"]) else [],
                                         f"Learned from approval #{aid}" + (f" by {by}" if by else ""))
                self.approve_change(ch["id"])
                ap["status"] = "approved + learned"
            return ap

    def request_change(self, agent_id, tools, domains, egress, reason):
        with LOCK:
            ch = {"id": len(self.changes) + 1, "agent": agent_id, "tools": tools, "domains": domains, "egress": egress,
                  "reason": reason, "status": "pending"}
            self.changes.append(ch)
            return ch

    def approve_change(self, cid):
        with LOCK:
            ch = next((c for c in self.changes if c["id"] == cid), None)
            if not ch or ch["status"] != "pending":
                return None
            a = self.agents[ch["agent"]]
            for key in ("tools", "domains", "egress"):
                a.manifest[key] = sorted(set(a.manifest[key]) | set(ch.get(key) or []))
            a.manifest["version"] += 1
            a.declared_tools |= set(ch["tools"])
            a.cusum = 0
            ch["status"], ch["version"] = "approved", a.manifest["version"]
            return ch

    def release(self, agent_id):
        with LOCK:
            a = self.agents[agent_id]
            a.status, a.revoked, a.risk, a.cusum, a.note = "healthy", set(), 0.0, 0, ""
            return a.view()

    def snapshot(self):
        with LOCK:
            evs = self.events
            return {
                "agents": [a.view() for a in self.agents.values()],
                "events": evs[-150:],
                "approvals": self.approvals[-30:],
                "changes": self.changes[-30:],
                "plugins": self.plugins[-20:],
                "documents": [{"name": n, "folder": f, "size": len(t)} for n, (f, t) in self.company.docs.items()],
                "external": self.company.external_received[-30:],
                "purchase_requests": self.company.purchase_requests[-10:],
                "risk_history": {a.id: a.risk_history[-80:] for a in self.agents.values()},
                "kpi": {"agents": len(self.agents), "actions": len(evs), "alerts": sum(1 for e in evs if e["score"] >= 40),
                        "restricted": sum(1 for a in self.agents.values() if a.status in ("restricted", "quarantined"))},
                "running": sorted(self.running), "log": self.log[-40:],
            }
