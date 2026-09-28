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
print("ALL OK")
server.shutdown()
