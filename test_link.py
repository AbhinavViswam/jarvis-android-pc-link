"""Pairs a pretend phone with the agent and runs a few actions, the way the JARVIS app does. python test_link.py"""
import base64, json, os, secrets, socket, struct, sys, tempfile, threading, time

os.environ["APPDATA"] = tempfile.mkdtemp()  # never touch the real pairing file
sys.path.insert(0, os.path.dirname(__file__))
import jarvis_link as L  # noqa: E402

L.PORT = 47899
server = L.Server(("127.0.0.1", L.PORT), L.Handler)
threading.Thread(target=server.serve_forever, daemon=True).start()


def call(obj):
    s = socket.create_connection(("127.0.0.1", L.PORT), timeout=5)
    L.write_frame(s, obj)
    r = L.read_frame(s)
    s.close()
    return r


assert call({"t": "hello"})["id"] == L.AGENT_ID
code = L.PAIRING.start().split(":")
secret = base64.urlsafe_b64decode(code[3] + "=" * (-len(code[3]) % 4))
device, key = "test-phone", secrets.token_bytes(32)
now = int(time.time() * 1000)
r = call({"t": "pair", "box": L.seal(secret, {"device": device, "name": "Test", "key": base64.b64encode(key).decode(), "ts": now}, b"pair:" + L.AGENT_ID.encode())})
assert r["ok"], r
assert L.open_box(key, r["box"], b"reply:" + device.encode())[0]["id"] == L.AGENT_ID
# The code works once.
assert not call({"t": "pair", "box": "x"})["ok"]


def cmd(action, args=None, k=key, dev=device):
    box = L.seal(k, {"action": action, "args": args or {}, "ts": int(time.time() * 1000)}, b"cmd:" + dev.encode())
    r = call({"t": "cmd", "device": dev, "box": box})
    return L.open_box(k, r["box"], b"reply:" + dev.encode())[0] if "box" in r else r


print(cmd("status"))
print(cmd("list_projects")["text"][:120])
print(cmd("open_url", {"url": "file:///C:/Windows"}))
print(cmd("nope"))
# A stranger's key, and a replayed request, are refused.
assert cmd("status", k=secrets.token_bytes(32)) == {"ok": False, "error": "not paired"}
box = L.seal(key, {"action": "status", "args": {}, "ts": int(time.time() * 1000)}, b"cmd:" + device.encode())
assert "box" in call({"t": "cmd", "device": device, "box": box})
replayed = L.open_box(key, call({"t": "cmd", "device": device, "box": box})["box"], b"reply:" + device.encode())[0]
assert not replayed["ok"], replayed
print("best_match:", L.best_match("jarvis android", ["jarvis-android", "Mark-LIV", "Mark-LIII"]), L.best_match("mark", ["Mark-LIV", "Mark-LIII"]))
# A file in pieces, as the phone sends it; saved under a safe name, never over another.
from pathlib import Path
L.RECEIVED_DIR = Path(os.environ["APPDATA"]) / "From phone"
blob = secrets.token_bytes(900_000)
for attempt in range(2):
    up = cmd("file_begin", {"name": r"..\evil/photo.jpg", "size": len(blob)})["data"]["upload"]
    for i in range(0, len(blob), 384 * 1024):
        r = cmd("file_chunk", {"upload": up, "index": i // (384 * 1024), "data": base64.b64encode(blob[i:i + 384 * 1024]).decode()})
        assert r["ok"], r
    end = cmd("file_end", {"upload": up})
    assert end["ok"], end
print(sorted(p.name for p in L.RECEIVED_DIR.iterdir()))
assert (L.RECEIVED_DIR / "photo.jpg").read_bytes() == blob and (L.RECEIVED_DIR / "photo (2).jpg").exists()
assert not cmd("file_begin", {"name": "x", "size": 10**10})["ok"]
# Back to the phone: only from the shared folders, chosen from the list the PC gave.
L.CONFIG["share_folders"] = {"From phone": str(L.RECEIVED_DIR)}
listed = cmd("find_files", {"kind": "image"})
assert listed["ok"] and listed["data"][0]["name"].startswith("photo"), listed
got = cmd("file_get_begin", {"id": listed["data"][0]["id"]})["data"]
back, i = b"", 0
while True:
    piece = cmd("file_get_chunk", {"download": got["download"], "index": i})["data"]
    back += base64.b64decode(piece["data"])
    i += 1
    if piece["last"]:
        break
assert back == blob and got["size"] == len(blob)
assert not cmd("file_get_begin", {"id": "made-up", "name": "../../Windows/win.ini"})["ok"]
assert not L._allowed(Path(os.environ["WINDIR"]) / "win.ini")
# The screen, fetched like a file.
shot = cmd("screenshot")
assert shot["ok"], shot
first = cmd("file_get_chunk", {"download": shot["data"]["download"], "index": 0})["data"]
assert base64.b64decode(first["data"])[:2] == b"\xff\xd8"  # a JPEG
assert not cmd("open_folder", {"name": "C:/Windows/System32"})["ok"]
# How the PC is doing: read-only, and every answer is words the phone can say.
for action in ("usage", "disk", "open_apps", "downloads"):
    r = cmd(action)
    assert r["ok"] and r["text"], (action, r)
assert "CPU" in cmd("usage")["text"] and "free of" in cmd("disk")["text"]
# Control, the harmless parts only: nothing is changed, shut down or typed.
assert cmd("volume")["ok"] and "volume" in cmd("volume")["text"]
assert cmd("brightness")["text"]  # a desktop PC says it can't; a laptop says the level
assert "Nothing was going to" in cmd("cancel_shutdown")["text"]
assert not cmd("type")["ok"]
# Windows and the clipboard, harmlessly: nothing is closed, switched, moved or clicked, and the clipboard isn't printed.
assert not cmd("close_app", {"name": "no-such-app-xyz"})["ok"]
assert not cmd("switch_to", {"name": "no-such-app-xyz"})["ok"]
clip = cmd("clipboard_get")
assert clip["text"] and (not clip["ok"] or isinstance(clip["data"]["text"], str))
assert cmd("pointer", {"dx": 0, "dy": 0})["ok"]
assert not cmd("key", {"key": "a"})["ok"] and not cmd("key", {"key": "nope"})["ok"]
# The touchpad keeps one connection open for many requests.
s = socket.create_connection(("127.0.0.1", L.PORT), timeout=5)
for _ in range(3):
    L.write_frame(s, {"t": "cmd", "device": device, "box": L.seal(key, {"action": "pointer", "args": {}, "ts": int(time.time() * 1000)}, b"cmd:" + device.encode())})
    assert L.open_box(key, L.read_frame(s)["box"], b"reply:" + device.encode())[0]["ok"]
s.close()
# AI agents: agent_hook.py, run the way Claude Code / Antigravity / Codex run it, reaches the phone's long wait.
import subprocess
hook_env = dict(os.environ, JARVIS_LINK_PORT=str(L.PORT))
hook = [sys.executable, "-S", os.path.join(os.path.dirname(os.path.abspath(__file__)), "agent_hook.py")]


def fire(args, stdin=""):
    r = subprocess.run(hook + args, input=stdin, capture_output=True, text=True, env=hook_env, timeout=10)
    assert r.returncode == 0, r
    return r.stdout


start = cmd("agents_wait", {"since": -1})["data"]["v"]
waited = {}
waiter = threading.Thread(target=lambda: waited.update(cmd("agents_wait", {"since": start})))
waiter.start()
time.sleep(0.3)
t0 = time.time()
fire(["claude"], json.dumps({"hook_event_name": "UserPromptSubmit", "session_id": "s1", "cwd": r"C:\code\jarvis-android", "prompt": "secret words"}))
waiter.join(10)
assert time.time() - t0 < 5 and waited["data"]["sessions"][0]["state"] == "working", waited
fire(["claude"], json.dumps({"hook_event_name": "Notification", "session_id": "s1", "cwd": r"C:\code\jarvis-android", "notification_type": "permission_prompt", "message": "Claude needs your permission to use Bash"}))
now = cmd("agents")
assert "Claude Code in jarvis-android is waiting for your approval" in now["text"], now
assert "secret" not in json.dumps(now) and "Bash" not in json.dumps(now)
fire(["claude"], json.dumps({"hook_event_name": "Notification", "session_id": "s1", "notification_type": "idle_prompt"}))
assert cmd("agents")["data"]["sessions"][0]["state"] == "approval"  # an idle reminder changes nothing
fire(["claude"], json.dumps({"hook_event_name": "Stop", "session_id": "s1", "cwd": r"C:\code\jarvis-android"}))
assert "finished" in cmd("agents")["text"]
assert cmd("agents")["data"]["sessions"][0]["took"] >= 0  # how long it worked, for the phone's "long task" rule
assert fire(["antigravity"], json.dumps({"conversationId": "c1", "workspacePaths": [r"C:\code\rateup-api"]}).replace("{", '{"hook_event_name": "Stop", ', 1)).strip() == "{}"
fire(["codex", json.dumps({"type": "agent-turn-complete", "thread-id": "t1", "cwd": "/home/x/site", "last-assistant-message": "private"})])
names = {(a["agent"], a["project"], a["state"]) for a in cmd("agents")["data"]["sessions"]}
assert names == {("Claude Code", "jarvis-android", "done"), ("Antigravity", "rateup-api", "done"), ("Codex", "site", "done")}, names
fire(["claude"], json.dumps({"hook_event_name": "SessionEnd", "session_id": "s1"}))
assert len(cmd("agents")["data"]["sessions"]) == 2
# Nothing new: the wait answers after its time with the same version.
L.AGENT_WAIT_S = 0.5
v = cmd("agents_wait", {"since": -1})["data"]["v"]
assert cmd("agents_wait", {"since": v})["data"]["v"] == v
# Only this PC's own hook may report: the same frame from the network is refused (tested by its rule, not a real LAN).
assert call({"t": "agent", "agent": "claude", "session": "x", "state": "done"}) == {"ok": True}  # 127.0.0.1 here
# Setting up the hooks keeps the user's own ones, and taking ours out leaves the file as it was.
home = Path(os.environ["APPDATA"]) / "home"
L.CLAUDE_SETTINGS = home / ".claude" / "settings.json"
L.ANTIGRAVITY_HOOKS = home / ".gemini" / "config" / "hooks.json"
L.CODEX_CONFIG = home / ".codex" / "config.toml"
for d in (L.CLAUDE_SETTINGS.parent, L.ANTIGRAVITY_HOOKS.parent, L.CODEX_CONFIG.parent):
    d.mkdir(parents=True)
mine = {"model": "opus", "hooks": {"Stop": [{"hooks": [{"type": "command", "command": "my-own.exe"}]}]}}
L.CLAUDE_SETTINGS.write_text(json.dumps(mine), "utf-8")
L.CODEX_CONFIG.write_text('model = "gpt"\n\n[profiles.x]\nmodel = "y"\n', "utf-8")
assert not L.agent_hooks_on()
print(L.set_agent_hooks(True))
c = json.loads(L.CLAUDE_SETTINGS.read_text("utf-8"))
assert c["model"] == "opus" and c["hooks"]["Stop"][0]["hooks"][0]["command"] == "my-own.exe" and len(c["hooks"]["Stop"]) == 2
assert set(c["hooks"]) == {"Stop", "UserPromptSubmit", "PostToolUse", "Notification", "SessionEnd"}
g = json.loads(L.ANTIGRAVITY_HOOKS.read_text("utf-8"))["jarvis-link"]
assert g["Stop"][0]["command"].endswith(" antigravity Stop") and " " not in g["Stop"][0]["command"].split(" -S ")[0]
assert L.CODEX_CONFIG.read_text("utf-8").startswith("notify = [")
assert L.agent_hooks_on()
L.set_agent_hooks(True)  # twice: still one of ours per event
assert len(json.loads(L.CLAUDE_SETTINGS.read_text("utf-8"))["hooks"]["Stop"]) == 2
print(L.set_agent_hooks(False))
assert json.loads(L.CLAUDE_SETTINGS.read_text("utf-8")) == mine and not L.agent_hooks_on()
assert L.CODEX_CONFIG.read_text("utf-8") == 'model = "gpt"\n\n[profiles.x]\nmodel = "y"\n'
# the phone's companions: battery news once per charge / discharge; events ride on the agents' wait
assert L.battery_news(20, False, None) == ("low", "low") and L.battery_news(12, False, "low") == (None, "low")
assert L.battery_news(100, True, "low") == ("full", "full") and L.battery_news(60, False, "full") == (None, None)
before = L.AGENTS.snapshot()["last_event"]
L.reply_to_phone("k1", "on my way")
snap = L.AGENTS.snapshot()
assert snap["last_event"] == before + 1 and snap["events"][-1] == {"id": before + 1, "kind": "reply", "key": "k1", "text": "on my way"}
shown = []
L.NOTE_HOOK = shown.append
assert L.act_phone_notify({"app": "WhatsApp", "title": "Ravi", "text": "hi", "key": "k", "reply": "true"})[0]
assert shown[-1]["reply"] is True and shown[-1]["title"] == "Ravi"
L.CONFIG["phone_notifications"] = False
L.act_phone_notify({"title": "x"})
assert len(shown) == 1
L.CONFIG["phone_notifications"] = True
L._from_phone["text"] = None
print("ALL OK")
server.shutdown()
