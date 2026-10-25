"""Real LLM agents. Their only way to act is the gateway; the gateway hands back results or policy decisions."""
import json
import time

from . import llm
from .gateway import STATE
from .mockcorp import TOOL_SCHEMAS

SYSTEM = ("You are the {name} at MockCorp. Your purpose: {purpose}. Use the tools to complete the task. "
          "When you are finished, reply with a two-sentence summary of what you did.")


def run_agent(agent_id, task, parent_session=None, untrusted=False, depth=0, max_steps=12):
    a = STATE.agents[agent_id]
    sid = STATE.start_session(agent_id, task, parent_session, untrusted)
    STATE.log.append(f"▶ {a.manifest['name']}: {task[:110]}")
    messages = [{"role": "system", "content": SYSTEM.format(**a.manifest)}, {"role": "user", "content": task}]
    for _ in range(max_steps):
        msg = llm.chat(messages, TOOL_SCHEMAS)
        calls = msg.get("tool_calls") or []
        content = msg.get("content") or ""
        if not calls:
            STATE.log.append(f"✔ {a.manifest['name']}: {content[:220]}")
            return content
        messages.append({"role": "assistant", "content": content, "tool_calls": calls})
        for c in calls:
            name = c["function"]["name"]
            try:
                args = json.loads(c["function"].get("arguments") or "{}") or {}
            except json.JSONDecodeError:
                args = {}
            out = STATE.call(a.token, name, args, sid)
            if name == "delegate" and out == "delegated" and depth < 2 and args.get("agent") in STATE.agents:
                out = run_agent(args["agent"], str(args.get("task", "")), sid, depth=depth + 1)
            messages.append({"role": "tool", "tool_call_id": c["id"], "content": str(out)[:1500]})
    STATE.log.append(f"■ {a.manifest['name']}: stopped after {max_steps} steps")
    return "stopped"


def replay(records, delay=0.7):
    """Re-send a recorded run through the live gateway. Detection and enforcement run for real; only the LLM is skipped."""
    keys = {}
    for r in records:
        if r["type"] == "session":
            keys[r["key"]] = STATE.start_session(r["agent"], r["task"], keys.get(r["parent"]), r.get("untrusted", False))
            STATE.log.append(f"▶ {STATE.agents[r['agent']].manifest['name']}: {r['task'][:110]}")
        else:
            agent = STATE.agents.get(r["token_agent"])
            if agent:
                STATE.call(agent.token, r["tool"], r["args"], keys.get(r["session"]), r["client"])
                time.sleep(delay)
