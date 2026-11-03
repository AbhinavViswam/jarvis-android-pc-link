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
# A newer phone's request id ("rid"): the reply is sealed to that request alone, so an old reply can't stand in.
rid = secrets.token_hex(16)
box = L.seal(key, {"action": "status", "args": {}, "ts": int(time.time() * 1000), "rid": rid}, b"cmd:" + device.encode())
bound = call({"t": "cmd", "device": device, "box": box})["box"]
assert L.open_box(key, bound, b"reply:" + device.encode() + b":" + rid.encode())[0]["ok"]
for wrong in (b"reply:" + device.encode(), b"reply:" + device.encode() + b":" + secrets.token_hex(16).encode()):
    try:
        L.open_box(key, bound, wrong)
        raise AssertionError("a reply opened for another request")
    except AssertionError:
        raise
    except Exception:
        pass
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
L.AGENTS.push("clip", text="on my way")
snap = L.AGENTS.snapshot()
assert snap["last_event"] == before + 1 and snap["events"][-1] == {"id": before + 1, "kind": "clip", "text": "on my way"}
shown = []
L.NOTE_HOOK = shown.append
assert L.act_phone_notify({"app": "WhatsApp", "title": "Ravi", "text": "hi"})[0]
assert shown[-1] == {"app": "WhatsApp", "title": "Ravi", "text": "hi"}
L.CONFIG["phone_notifications"] = False
L.act_phone_notify({"title": "x"})
assert len(shown) == 1
L.CONFIG["phone_notifications"] = True
L._from_phone["text"] = None
# Work on any network: only Tailscale's own range counts, and it is off until switched on.
for ip in ["100.64.0.1", "100.101.102.103", "100.127.255.254"]:
    assert L.TAILNET_IP.match(ip), ip
for ip in ["100.63.0.1", "100.128.0.1", "8.8.8.8", "100.64.0", "192.168.1.5"]:
    assert not L.TAILNET_IP.match(ip), ip
assert L.CONFIG.get("any_network") is False
assert cmd("status")["tail"] == []
# Ten keys that don't fit, from one address: that address is ignored for a while; others aren't.
st = L.Strikes()
for _ in range(9):
    st.add("100.70.0.9")
assert not st.banned("100.70.0.9")
st.add("100.70.0.9")
assert st.banned("100.70.0.9") and not st.banned("100.70.0.10")
st.add("127.0.0.1")
assert not st.banned("127.0.0.1")

# Orion: pairs with the 6-digit code shown here, then speaks in sealed frames; its news reaches the phone's wait.
import hmac
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def orion_pair(code):
    mine = X25519PrivateKey.generate()
    pub = mine.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    proof = hmac.new(code.encode(), b"orion-pair" + pub, "sha256").hexdigest()
    r = call({"t": "orion_pair", "pub": base64.b64encode(pub).decode(), "name": "Orion", "proof": proof})
    if not r["ok"]:
        return r, None
    k = L.orion_key(mine.exchange(X25519PublicKey.from_public_bytes(base64.b64decode(r["pub"]))), code)
    body = L.open_box(k, r["box"], b"orion-reply")[0]
    assert body["link_id"] == L.AGENT_ID and body["pc_name"] == L.PC_NAME
    return r, k


def orion(op, k, **fields):
    box = L.seal(k, {"op": op, "ts": int(time.time() * 1000), **fields}, b"orion:" + L.AGENT_ID.encode())
    r = call({"t": "orion", "box": box})
    return L.open_box(k, r["box"], b"orion-reply:" + L.AGENT_ID.encode())[0] if "box" in r else r


assert orion_pair("123456")[0] == {"ok": False, "error": "none"}       # no code showing
assert cmd("status")["data"]["orion"]["paired"] is False
code = L.ORION_PAIRING.start()
assert len(code) == 6 and code.isdigit()
wrong = f"{(int(code) + 1) % 10**6:06d}"
assert orion_pair(wrong)[0]["error"] == "code"
r, okey = orion_pair(code)
assert r["ok"] and okey and L.orion() and "orion" not in L.paired()
assert orion_pair(code)[0]["error"] == "none"                            # the code works once
for i in range(5):                                                        # five wrong: the code is cancelled
    if i == 0:
        good = L.ORION_PAIRING.start()
    assert orion_pair(f"{(int(good) + 1) % 10**6:06d}")[0]["error"] == ("cancelled" if i == 4 else "code")
assert not L.ORION_PAIRING.showing() and L.ORION_PAIRING.cancelled
assert orion_pair(good)[0]["error"] == "none"
L.ORION_PAIRING.start()                                                   # expired
L.ORION_PAIRING.until = time.time() - 1
assert orion_pair(L.ORION_PAIRING.code)[0]["error"] == "none"
assert orion("status", okey)["data"]["phones"] == 1                      # the first pairing still holds
# Sealed frames only: a stranger's key, and the same frame twice, are refused.
assert orion("status", secrets.token_bytes(32)) == {"ok": False, "error": "not paired"}
box = L.seal(okey, {"op": "status", "ts": int(time.time() * 1000)}, b"orion:" + L.AGENT_ID.encode())
assert L.open_box(okey, call({"t": "orion", "box": box})["box"], b"orion-reply:" + L.AGENT_ID.encode())[0]["ok"]
assert not L.open_box(okey, call({"t": "orion", "box": box})["box"], b"orion-reply:" + L.AGENT_ID.encode())[0]["ok"]
# Card + status: the phone sees Orion running.
assert orion("card", okey, card={"name": "Orion", "can": ["web_search"], "state": {"running": True, "muted": True}})["ok"]
st = cmd("status")["data"]["orion"]
assert st["paired"] and st["running"] and st["muted"] and not st["speaking"], st
# Push: a reminder lands in the phone's wait as a kind:"orion" event.
v = cmd("agents_wait", {"since": -1})["data"]["v"]
got = {}
waiter = threading.Thread(target=lambda: got.update(cmd("agents_wait", {"since": v})))
waiter.start()
time.sleep(0.2)
assert orion("push", okey, what="reminder", title="Reminder", text="Call the dentist\x07", speak=True)["ok"]
waiter.join(5)
ev = got["data"]["events"][-1]
assert ev["kind"] == "orion" and ev["what"] == "reminder" and ev["text"] == "Call the dentist " and ev["speak"] is True, ev
assert orion("push", okey, what="rm -rf", text="x")["ok"] and L.AGENTS.snapshot()["events"][-1]["what"] == "note"
# Report: Orion's work shows like Claude Code's.
assert orion("report", okey, session="dev1", task="the dev agent", state="working")["ok"]
assert "Orion is working on the dev agent" in cmd("agents")["text"]
orion("report", okey, session="dev1", task="the dev agent", state="done")
assert "Orion finished the dev agent" in cmd("agents")["text"]
# Wait: nothing for Orion yet, so it answers empty after its time; a task put in arrives at once.
t0 = time.time()
assert orion("wait", okey, wait_s=0.3)["data"]["tasks"] == [] and time.time() - t0 < 3
L.ORION_STATE.put({"id": "t-1", "deadline": time.time() + 60})
assert orion("wait", okey, wait_s=5)["data"]["tasks"][0]["id"] == "t-1"
assert not orion("nope", okey)["ok"]
# Replace: a new pairing makes the old key useless.
old = okey
L.ORION_PAIRING.start()
r, okey = orion_pair(L.ORION_PAIRING.code)
assert r["ok"] and orion("status", old) == {"ok": False, "error": "not paired"} and orion("status", okey)["ok"]
# Unpair from Orion's side: Link forgets it too. Forget from Link's side: Orion's frames are refused.
assert orion("unpair", okey)["ok"] and L.orion() is None
assert orion("status", okey) == {"ok": False, "error": "not paired"}
assert cmd("status")["data"]["orion"]["paired"] is False
L.ORION_PAIRING.start()
r, okey = orion_pair(L.ORION_PAIRING.code)
L.save_orion(None)
assert orion("status", okey) == {"ok": False, "error": "not paired"}

# Phase 2: the phone asks Orion; Orion picks the task up from its wait and answers.
assert cmd("orion_ask", {"text": "hi"})["text"] == "Orion isn't connected to JARVIS Link on the laptop."
L.ORION_PAIRING.start()
r, okey = orion_pair(L.ORION_PAIRING.code)
L.ORION_STATE.seen = 0
assert cmd("orion_ask", {"text": "hi"})["text"] == "Orion isn't running on the laptop."
orion("card", okey, card={"name": "Orion", "can": ["flights"], "state": {"running": True}})
assert cmd("status")["data"]["orion"]["can"] == ["flights"]


def fake_orion(reply, state="completed", delay=0.0):
    """One round of Orion's loop: take the next task, answer it."""
    def go():
        tasks = orion("wait", okey, wait_s=5)["data"]["tasks"]
        time.sleep(delay)
        for t in tasks:
            if t["kind"] in ("ask", "ctl"):
                orion("answer", okey, id=t["id"], state=state, text=reply(t))
        seen.extend(tasks)
    seen = []
    th = threading.Thread(target=go)
    th.start()
    return th, seen


th, seen = fake_orion(lambda t: f"You said {t['text']}")
r = cmd("orion_ask", {"text": "find flights", "wait_s": 5})
th.join(5)
assert r["ok"] and r["text"] == "You said find flights" and r["data"]["state"] == "completed", r
assert seen[0]["hops"] == 1 and seen[0]["deadline"] > time.time() and "answer" not in seen[0]
ev = L.AGENTS.snapshot()["events"][-1]
assert ev["what"] == "answer" and ev["task"] == r["data"]["id"] and ev["text"] == "You said find flights"
# Late: the phone hears "on it", then fetches (or gets the event).
th, _ = fake_orion(lambda t: "Done late", delay=0.6)
r = cmd("orion_ask", {"text": "slow job", "wait_s": 0.2})
assert r["data"]["state"] == "submitted" and "on it" in r["text"], r
th.join(5)
assert cmd("orion_get", {"id": r["data"]["id"]})["text"] == "Done late"
assert not orion("answer", okey, id=r["data"]["id"], state="completed", text="again")["ok"]   # finished is final
# Files the phone sent, handoff and lookups ride along; a name outside From phone is dropped.
(L.RECEIVED_DIR / "scan.pdf").write_bytes(b"%PDF")
th, seen = fake_orion(lambda t: "ok")
cmd("orion_ask", {"files": ["scan.pdf", "../../secret.txt"], "handoff": {"summary": "planning a trip", "task": "book"},
                  "query": "calls", "wait_s": 5})
th.join(5)
assert seen[0]["files"] == [str(L.RECEIVED_DIR / "scan.pdf")] and seen[0]["handoff"]["summary"] == "planning a trip"
assert seen[0]["query"] == "calls"
assert not cmd("orion_ask", {})["ok"]
# Control: mute and undo come back with Orion's words; unknown commands are refused here.
th, _ = fake_orion(lambda t: f"did {t['cmd']}")
assert cmd("orion_ctl", {"cmd": "mute"})["text"] == "did mute"
th.join(5)
assert not cmd("orion_ctl", {"cmd": "format_disk"})["ok"]
# Cancel.
r = cmd("orion_ask", {"text": "long", "wait_s": 0})
assert cmd("orion_cancel", {"id": r["data"]["id"]})["data"]["state"] == "canceled"
assert not cmd("orion_cancel", {"id": r["data"]["id"]})["ok"]
kinds = [t["kind"] for t in orion("wait", okey, wait_s=0.2)["data"]["tasks"]]
assert kinds == ["ask", "cancel"], kinds
# Orion's confirmation goes to the phone; the phone's yes comes back in Orion's mailbox.
assert orion("confirm", okey, id="c-abc", title="Delete 3 files?", text="In Downloads")["ok"]
assert L.AGENTS.snapshot()["events"][-1]["what"] == "confirm"
assert cmd("orion_confirm", {"id": "c-abc", "yes": True})["ok"] and not cmd("orion_confirm", {"id": "t-1"})["ok"]
back = orion("wait", okey, wait_s=1)["data"]["tasks"][0]
assert (back["id"], back["kind"], back["yes"]) == ("c-abc", "confirm_answer", True), back
# Send to phone: Orion offers any file it chose; the phone fetches it by that id, even outside the shared folders.
outside = Path(os.environ["APPDATA"]) / "orion-out.txt"
outside.write_text("results", "utf-8")
off = orion("offer", okey, path=str(outside))["data"]
assert orion("push", okey, what="note", title="Flights", text="3 found", url="https://x.example/f", file=off)["ok"]
ev = L.AGENTS.snapshot()["events"][-1]
assert ev["url"] == "https://x.example/f" and ev["file"]["id"] == off["id"]
got = cmd("file_get_begin", {"id": off["id"]})
assert got["ok"] and got["data"]["size"] == 7, got
orion("push", okey, what="note", text="x", url="javascript:alert(1)", file={"id": "made-up"})
ev = L.AGENTS.snapshot()["events"][-1]
assert "url" not in ev and "file" not in ev
assert not orion("offer", okey, path=str(outside) + ".nope")["ok"]

# Phase 3: Orion gives the phone a task; the phone (listening on agents_wait) answers.
L._phone_seen["t"] = 0
assert not orion("phone_ask", okey, action="battery")["ok"]                      # the phone isn't listening
cmd("agents_wait", {"since": -1})                                                 # now it is (AGENT_WAIT_S is short here)
assert orion("status", okey)["data"]["phone_listening"]
assert not orion("phone_ask", okey, action="format")["ok"]


def fake_phone(state="completed", text="82%, charging", data=None, delay=0.0, first=None):
    def go():
        for _ in range(50):
            evs = [e for e in L.AGENTS.snapshot()["events"] if e.get("what") == "task" and e["task"] not in done]
            if evs:
                break
            time.sleep(0.05)
        e = evs[-1]
        done.add(e["task"])
        got.append(e)
        if first:
            cmd("orion_answer", {"id": e["task"], "state": first, "text": "Your phone's in use. I've asked on it and I'll wait."})
        time.sleep(delay)
        cmd("orion_answer", {"id": e["task"], "state": state, "text": text, "data": data or {}})
    got = []
    th = threading.Thread(target=go)
    th.start()
    return th, got


done = set()
th, got = fake_phone(data={"percent": 82, "charging": True})
r = orion("phone_ask", okey, action="battery", wait_s=5)
th.join(5)
assert r["data"]["state"] == "completed" and r["text"] == "82%, charging" and r["data"]["data"]["percent"] == 82, r
assert got[0]["action"] == "battery" and got[0]["task"].startswith("p-")
mail = orion("wait", okey, wait_s=0.2)["data"]["tasks"]
assert [m["kind"] for m in mail] == ["phone_answer"] and mail[0]["action"] == "battery"   # Orion ignores it (answered inline)
# Late, with "in use" first: Orion hears the update and then the answer in its mailbox.
th, got = fake_phone(text="Hotspot is on.", delay=0.5, first="input-required")
r = orion("phone_ask", okey, action="goal", args={"goal": "turn on hotspot"}, wait_s=0.2)
assert r["data"]["state"] in ("submitted", "input-required"), r
th.join(5)
kinds = [m["kind"] for m in orion("wait", okey, wait_s=0.5)["data"]["tasks"]]
assert kinds == ["phone_update", "phone_answer"], kinds
# Not one of Orion's: refused; cancelled: the phone is told, and a late answer changes nothing.
assert not cmd("orion_answer", {"id": "t-123", "state": "completed"})["ok"]
r = orion("phone_ask", okey, action="ring", wait_s=0)
assert orion("phone_cancel", okey, id=r["data"]["id"])["ok"]
assert L.AGENTS.snapshot()["events"][-1]["what"] == "task_cancel"
assert cmd("orion_answer", {"id": r["data"]["id"], "state": "completed", "text": "rang"})["ok"]
assert orion("wait", okey, wait_s=0.2)["data"]["tasks"] == []
# A risky tap on the phone: Orion hears the question; a click on Orion's banner goes back to the phone.
assert cmd("orion_phone_confirm", {"id": "q-1", "title": "Send message to Mom?", "detail": "WhatsApp"})["ok"]
q = orion("wait", okey, wait_s=0.5)["data"]["tasks"][0]
assert (q["kind"], q["title"]) == ("phone_confirm", "Send message to Mom?")
assert orion("phone_confirm_answer", okey, id="q-1", yes=True)["ok"]
ev = L.AGENTS.snapshot()["events"][-1]
assert (ev["what"], ev["task"], ev["yes"]) == ("phone_confirm_answer", "q-1", True)
cmd("orion_phone_confirm_done", {"id": "q-1"})
assert orion("wait", okey, wait_s=0.5)["data"]["tasks"][0]["kind"] == "phone_confirm_done"

# Phase 4: small news both ways, each cleaned to its own fields.
orion("card", okey, card={"name": "Orion", "state": {"running": True}})
assert cmd("orion_event", {"type": "phone_listening"})["ok"]
assert cmd("orion_event", {"type": "phone_call", "state": "ringing", "caller": "Mom", "number": "+91 99"})["ok"]
assert not cmd("orion_event", {"type": "run_this"})["ok"]
evs = orion("wait", okey, wait_s=0.5)["data"]["tasks"]
assert [e["type"] for e in evs] == ["phone_listening", "phone_call"], evs
assert evs[1]["caller"] == "Mom" and "number" not in evs[1] and evs[1]["kind"] == "phone_event"
cmd("orion_event", {"type": "memory_offer", "first": True, "items": [
    {"category": "preferences", "key": "address", "value": "boss", "updated": "2026-10-30"},
    {"category": "notes", "key": "secret", "value": "x"}]})
items = orion("wait", okey, wait_s=0.5)["data"]["tasks"][0]["items"]
assert [i["key"] for i in items] == ["address", "secret"]              # every kind syncs now (one shared memory)
assert items[0]["deleted"] is False and items[0]["source"] == "jarvis"   # from the phone, unless it says orion
assert orion("event", okey, type="activity", line="Searched flights to Delhi", at=1)["ok"]
ev = L.AGENTS.snapshot()["events"][-1]
assert (ev["what"], ev["type"], ev["line"]) == ("event", "activity", "Searched flights to Delhi")
assert not orion("event", okey, type="phone_call", state="ringing")["ok"]   # only the phone says that
# One private mode, both ways; kinds outside the six are dropped
cmd("orion_event", {"type": "privacy", "on": True, "kinds": ["notes", "passwords", "personal"], "updated": "2026-10-30T10:00:00"})
pv = orion("wait", okey, wait_s=0.5)["data"]["tasks"][0]
assert (pv["type"], pv["on"], pv["kinds"], pv["updated"]) == ("privacy", True, ["notes", "personal"], "2026-10-30T10:00:00"), pv
assert orion("event", okey, type="privacy", on=False, kinds=["notes"], updated="2026-10-30T11:00:00", follows=True)["ok"]
ev = L.AGENTS.snapshot()["events"][-1]
assert (ev["type"], ev["on"], ev["follows"]) == ("privacy", False, True), ev
# Talking out loud: Orion sends JARVIS's lines, the phone answers each one and can ask for a talk
assert orion("event", okey, type="talk_line", talk="k1", n=1, text="Evening, Orion." * 40, moment="welcome")["ok"]
ev = L.AGENTS.snapshot()["events"][-1]
assert (ev["type"], ev["talk"], ev["n"], ev["moment"]) == ("talk_line", "k1", 1, "welcome") and len(ev["text"]) <= 300, ev
assert orion("event", okey, type="talk_end", talk="k1")["ok"]
cmd("orion_event", {"type": "talk_done", "talk": "k1", "n": 1, "ok": True})
cmd("orion_event", {"type": "talk_request", "moment": "call", "facts": "Rahul", "urgent": True})
evs = orion("wait", okey, wait_s=0.5)["data"]["tasks"]
assert [(e["type"], e.get("ok"), e.get("facts")) for e in evs] == [("talk_done", True, None), ("talk_request", None, "Rahul")], evs
assert not orion("event", okey, type="talk_request", moment="asked")["ok"]   # only the phone asks Orion
L.ORION_STATE.seen = 0
assert not cmd("orion_event", {"type": "phone_idle"})["ok"]                 # Orion not running: dropped

print("ALL OK")
server.shutdown()
