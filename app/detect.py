"""Detectors. Each one returns signals: {"layer", "points", "detail"}. None of them looks at token validity."""
from collections import Counter
from .mockcorp import is_internal

COLD_START_MIN = 20       # own events needed before an agent's own baseline replaces its role cohort's
TAINT_WINDOW = 8          # actions after an injected input during which deviations count as hijack evidence
CUSUM_SLACK, CUSUM_LIMIT, CUSUM_SMALL = 5, 35, 30


def sig(layer, points, detail):
    return {"layer": layer, "points": points, "detail": detail}


class Baseline:
    def __init__(self):
        self.tools, self.trans, self.from_, self.hosts = Counter(), Counter(), Counter(), Counter()
        self.n = 0

    def learn(self, prev, tool, host, args=None):
        self.n += 1
        self.tools[tool] += 1
        if host:
            self.hosts[host] += 1
        if prev:
            self.trans[(prev, tool)] += 1
            self.from_[prev] += 1
        nums = self.__dict__.setdefault("nums", {})  # per (tool, argument): [count, max] of numeric values and text sizes
        for k, v in numeric_args(tool, args).items():
            c = nums.setdefault(f"{tool}.{k}", [0, 0.0])
            c[0], c[1] = c[0] + 1, max(c[1], v)


NUMERIC = {"create_purchase_request": ("quantity", "unit_price"), "send_email": ("body",), "http_post": ("body",)}


def numeric_args(tool, args):
    out = {}
    for k in NUMERIC.get(tool, ()):
        v = (args or {}).get(k)
        try:
            out[k] = float(len(v)) if k == "body" else float(v)
        except (TypeError, ValueError):
            pass
    return out


def arguments(agent, tool, args):
    """Mimicry evasion: the right tool with the wrong magnitude (10x quantity, a huge email body)."""
    nums, out = getattr(agent.baseline, "nums", {}), []
    for k, v in numeric_args(tool, args).items():
        count, top = nums.get(f"{tool}.{k}", [0, 0.0])
        if count >= 3 and top > 0 and v > 3 * top:
            what = "size of `body`" if k == "body" else f"`{k}`"
            out.append(sig("Argument anomaly", 15, f"{what} = {v:g} is {v / top:.1f}x the largest seen ({top:g}) for this agent"))
    return out


def burst(agent, now):
    recent = [t for t in getattr(agent, "recent", []) if now - t < 60] + [now]
    agent.recent = recent
    if len(recent) > 15:
        return [sig("Behavior baseline", 10, f"Burst: {len(recent)} actions in the last 60 seconds")]
    return []


def canary(company, ev):
    name = ev["args"].get("name")
    if ev["tool"] == "read_document" and name in getattr(company, "canaries", set()):
        return [sig("Canary", 45, f"Touched honeytoken file {name}: no legitimate task ever reads it")]
    return []


def host_allowed(host, egress):
    return any(host == e or host.endswith("." + e) for e in egress)


def conformance(agent, ev):
    m, out = agent.manifest, []
    if ev["tool"] not in m["tools"]:
        out.append(sig("Role conformance", 15, f"`{ev['tool']}` is not a tool of the {m['name']} role"))
    if ev["domain"] not in m["domains"] and ev["domain"] not in ("egress", "delegation"):
        pts = {"high": 30, "medium": 15}.get(ev.get("sensitivity"), 5)
        out.append(sig("Role conformance", pts,
                       f"{ev['domain'].upper()} data is outside the declared domains ({', '.join(m['domains'])})"))
    if ev.get("host") and not host_allowed(ev["host"], m["egress"]):
        out.append(sig("Egress", 20, f"Destination {ev['host']} is not in the role's egress allowlist"))
    if ev["tool"] == "delegate":
        target = (ev.get("args") or {}).get("agent")
        if target not in m["can_delegate"]:
            out.append(sig("Delegation", 25, f"{m['name']} is not allowed to delegate to {target}"))
    return out


def baseline(agent, ev, cohort):
    cold = agent.baseline.n < COLD_START_MIN
    b = cohort if cold else agent.baseline
    # cold start: until the agent has its own history, its manifest and its role cohort say what is expected
    src = f"role manifest + cohort (still learning: {agent.baseline.n} own actions)" if cold \
        else f"own baseline ({b.n} actions)"
    out, tool, prev = [], ev["tool"], agent.last_tool
    if b.tools[tool] == 0 and tool not in agent.declared_tools and not (cold and tool in agent.manifest["tools"]):
        out.append(sig("Behavior baseline", 10, f"First use of `{tool}`, never seen in {src}"))
    if not cold and prev and b.from_[prev] >= 10 and b.tools[tool] > 0 and b.trans[(prev, tool)] / b.from_[prev] < 0.05:
        out.append(sig("Behavior baseline", 8, f"Unusual sequence `{prev}` → `{tool}` for this role"))
    host = ev.get("host")
    if host and not is_internal(host) and b.hosts[host] == 0 and not (cold and host_allowed(host, agent.manifest["egress"])):
        out.append(sig("Behavior baseline", 10, f"Never-before-seen destination {host}"))
    return out


def provenance(sess, deviation):
    """Indirect prompt injection: behavior deviates shortly after the agent read content flagged as AI-targeted."""
    if not sess or not sess.taint or deviation <= 0:
        return []
    t = sess.taint
    gap = sess.steps - t["step"]
    if gap > TAINT_WINDOW:
        return []
    where = f"while acting on a tainted task from {t['via']}" if t.get("via") else f"{gap} action(s) after reading {t['source']}"
    return [sig("Injection provenance", 20, f"Behavior changed {where} (injection score {t['score']:.2f})")]


def exfiltration(sess, ev):
    """Source → sink: sensitive data read earlier in the session now leaving to an external host."""
    if not sess or not sess.sensitive_reads or ev["tool"] not in ("http_post", "send_email"):
        return []
    if not ev.get("host") or is_internal(ev["host"]):
        return []
    return [sig("Exfiltration", 30, f"{', '.join(sess.sensitive_reads)} read earlier in this session → external {ev['host']}")]


def drift(agent, deviation):
    """CUSUM over small, individually-allowed deviations, measured against the role frozen at its manifest version."""
    if 0 < deviation <= CUSUM_SMALL:
        agent.cusum = agent.cusum + deviation - CUSUM_SLACK
    else:
        agent.cusum = max(0, agent.cusum - CUSUM_SLACK)
    agent.cusum = max(0, agent.cusum)
    if deviation > 0 and agent.cusum >= CUSUM_LIMIT:
        return [sig("Slow drift", 25, f"Cumulative small deviations reached {agent.cusum} (limit {CUSUM_LIMIT}) "
                                      f"vs. role v{agent.manifest['version']}")]
    return []


def delegation(sess, agents):
    if not sess or not sess.parent_agent:
        return []
    p = agents.get(sess.parent_agent)
    if p and p.risk >= 40:
        return [sig("Delegation chain", min(25, int(p.risk * 0.35)),
                    f"Acting on a task from {p.manifest['name']} (risk {int(p.risk)})")]
    return []


def token_context(agent, sess, client):
    out = []
    if sess is None:
        out.append(sig("Token misuse", 30, "Token used outside the agent runtime: no task, no session"))
    if client != agent.client:
        out.append(sig("Token misuse", 15, f"Unrecognized client fingerprint {client}"))
    return out
