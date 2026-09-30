"""
Tells JARVIS Link what an AI agent on this PC is doing, so JARVIS on the phone can say when it has finished or is
waiting for you. Tray → Watch AI agents sets it up in Claude Code, Antigravity and Codex; any other agent that can run a
command on its events can use it too:

    python agent_hook.py <agent> [event]

The event's details arrive as JSON on stdin (from Codex, as the last argument). Only the agent's name, the name of the
project folder, a session id and the state are passed on: never prompts, code, messages or what a tool was doing.

Standard library only, and always exits at once with 0: it must never slow down or block the agent, whether or not
JARVIS Link is running.
"""
import json
import os
import socket
import struct
import sys

PORT = int(os.environ.get("JARVIS_LINK_PORT", "47800"))  # another port only for test_link.py

WORKING = {"userpromptsubmit", "posttooluse", "preinvocation", "beforeagent", "beforesubmitprompt"}
DONE = {"stop", "agent-turn-complete", "afteragent"}
ENDED = {"sessionend"}


def state_of(event: str, p: dict) -> str | None:
    """working / approval / question / done / ended, or None for an event that says nothing new."""
    e = event.lower()
    if e in WORKING:
        return "working"
    if e in DONE:
        return "done"
    if e in ENDED:
        return "ended"
    if e == "permissionrequest" or "approval" in e:
        return "approval"
    if e == "notification":
        kind = str(p.get("notification_type") or "").lower()
        if kind == "permission_prompt" or (not kind and "permission" in str(p.get("message") or "").lower()):
            return "approval"
        if kind == "elicitation_dialog":
            return "question"
    # idle_prompt ("waiting for your input", a minute after it finished), SessionStart, …: nothing new.
    return None


def details(argv: list[str]) -> dict:
    raw = ""
    if len(argv) > 2 and argv[-1].lstrip().startswith("{"):  # Codex: the JSON is the last argument
        raw = argv[-1]
    elif not sys.stdin.isatty():
        raw = sys.stdin.read()
    try:
        p = json.loads(raw or "{}")
        return p if isinstance(p, dict) else {}
    except ValueError:
        return {}


def project_of(p: dict) -> str:
    folders = p.get("workspacePaths") or p.get("workspace_roots") or []
    where = p.get("cwd") or (folders[0] if isinstance(folders, list) and folders else None) or os.getcwd()
    return os.path.basename(os.path.normpath(str(where)))[:60]


def main() -> None:
    agent = (sys.argv[1] if len(sys.argv) > 1 else "agent").lower()[:20]
    p = details(sys.argv)
    event = sys.argv[2] if len(sys.argv) > 2 and not sys.argv[2].lstrip().startswith("{") else ""
    event = event or str(p.get("hook_event_name") or p.get("type") or "")
    state = state_of(event, p)
    if state is None:
        return
    session = str(p.get("session_id") or p.get("conversationId") or p.get("thread-id") or p.get("conversation_id") or agent)[:64]
    frame = json.dumps({"t": "agent", "agent": agent, "session": session, "project": project_of(p), "state": state}).encode()
    # 0.1 s: on this PC JARVIS Link answers in under a millisecond, and Windows spends half a second retrying a port
    # nobody is listening on — which, after every tool call, would slow the agent down whenever JARVIS Link is off.
    with socket.create_connection(("127.0.0.1", PORT), timeout=0.1) as s:
        s.settimeout(0.5)
        s.sendall(struct.pack(">I", len(frame)) + frame)
        s.recv(256)  # the reply, so JARVIS Link isn't left writing to a closed connection


if __name__ == "__main__":
    try:
        main()
    except Exception:
        pass  # JARVIS Link not running, or anything else: the agent carries on regardless
    if len(sys.argv) > 1 and sys.argv[1].lower() == "antigravity":
        print("{}")  # Antigravity reads a hook's output as JSON: an empty answer changes nothing
    sys.exit(0)
