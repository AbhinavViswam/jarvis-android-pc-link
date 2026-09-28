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
print("ALL OK")
server.shutdown()
