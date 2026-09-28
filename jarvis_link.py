"""
JARVIS Link — lets JARVIS on your phone do a few things on this PC, over your home Wi-Fi.

  "Open my JARVIS project on the laptop", "open Spotify on the PC", "send this link to my laptop",
  "lock the laptop", "pause the music on the PC", "is the laptop on?"

How it's kept safe
  * Only phones paired once by QR code are listened to. Pairing is remembered (paired.json), so it survives
    restarts; remove a phone from the tray menu at any time.
  * Every request and reply is encrypted and authenticated (AES-256-GCM) with that phone's own key, carries the
    time, and is refused if it is old or a replay.
  * Only the fixed actions in ACTIONS below exist. Nothing the phone sends is ever run as a command or script.
  * Your home network only: found by the phone with mDNS, nothing is opened to the internet.

Runs in the system tray. Needs: pip install -r requirements.txt
"""

from __future__ import annotations

import base64
import ctypes
import difflib
import io
import json
import logging
import os
import queue
import re
import secrets
import shutil
import socket
import socketserver
import struct
import subprocess
import sys
import threading
import time
import uuid
import webbrowser
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

APP = "JARVIS Link"
VERSION = 1
PORT = 47800
SERVICE = "_jarvislink._tcp.local."
HOME = Path(os.environ.get("APPDATA", Path.home())) / APP
CONFIG_FILE = HOME / "config.json"
PAIRED_FILE = HOME / "paired.json"
LOG_FILE = HOME / "link.log"
STARTUP_FILE = Path(os.environ.get("APPDATA", "")) / "Microsoft/Windows/Start Menu/Programs/Startup/JARVIS Link.vbs"

PAIR_WINDOW_S = 180           # a pairing QR code works for 3 minutes, once
MAX_FRAME = 256 * 1024        # requests are tiny; anything bigger is refused
MAX_SKEW_S = 120              # a request older (or newer) than this is refused
PROJECT_MARKERS = {".git", "package.json", "build.gradle", "build.gradle.kts", "settings.gradle.kts", "pyproject.toml",
                   "requirements.txt", "setup.py", "Cargo.toml", "go.mod", "pom.xml", "composer.json", "pubspec.yaml"}
SKIP_DIRS = {"node_modules", ".venv", "venv", "env", "__pycache__", "build", "dist", ".gradle", ".idea", "target", "bin", "obj", ".git"}

HOME.mkdir(parents=True, exist_ok=True)
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("link")


# ---------------------------------------------------------------------------------------------- storage

def _load(path: Path, default):
    try:
        return json.loads(path.read_text("utf-8"))
    except Exception:
        return default


def _save(path: Path, data) -> None:
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2), "utf-8")
    tmp.replace(path)


def load_config() -> dict:
    c = _load(CONFIG_FILE, {})
    changed = False
    if "id" not in c:
        c["id"] = uuid.uuid4().hex
        changed = True
    if "workspaces" not in c and "project_roots" not in c:
        # Named project folders: "open the RateUp website" picks the website in RateUp. Edit in Project folders….
        home = Path.home()
        guesses = [home / "Documents", home / "Projects", home / "source" / "repos", home / "StudioProjects"]
        c["workspaces"] = {p.name: str(p) for p in guesses if p.is_dir()}
        changed = True
    c.setdefault("aliases", {})          # "jarvis": "C:\\...\\jarvis-android"
    c.setdefault("editor", "code")       # a command on PATH; the folder is passed to it. "explorer" opens the folder.
    c.setdefault("name", socket.gethostname())
    if changed:
        _save(CONFIG_FILE, c)
    return c


CONFIG = load_config()
AGENT_ID: str = CONFIG["id"]
PC_NAME: str = CONFIG["name"]

_paired_lock = threading.Lock()


def paired() -> dict:
    with _paired_lock:
        return _load(PAIRED_FILE, {})


def save_paired(p: dict) -> None:
    with _paired_lock:
        _save(PAIRED_FILE, p)


# ---------------------------------------------------------------------------------------------- crypto

def seal(key: bytes, obj: dict, aad: bytes) -> str:
    nonce = secrets.token_bytes(12)
    return base64.b64encode(nonce + AESGCM(key).encrypt(nonce, json.dumps(obj).encode("utf-8"), aad)).decode()


def open_box(key: bytes, box: str, aad: bytes) -> tuple[dict, bytes]:
    raw = base64.b64decode(box)
    nonce, ct = raw[:12], raw[12:]
    return json.loads(AESGCM(key).decrypt(nonce, ct, aad).decode("utf-8")), nonce


class Replays:
    """Nonces seen in the last few minutes: the same request twice is refused."""

    def __init__(self):
        self._seen: dict[bytes, float] = {}
        self._lock = threading.Lock()

    def fresh(self, nonce: bytes) -> bool:
        now = time.time()
        with self._lock:
            for n, t in list(self._seen.items()):
                if now - t > MAX_SKEW_S * 2:
                    del self._seen[n]
            if nonce in self._seen:
                return False
            self._seen[nonce] = now
            return True


REPLAYS = Replays()


# ---------------------------------------------------------------------------------------------- pairing

class Pairing:
    """The one pairing code on offer, if any: a secret shown in the QR code, good for one phone, for 3 minutes."""

    def __init__(self):
        self.secret: bytes | None = None
        self.until = 0.0
        self.lock = threading.Lock()
        self.on_paired = lambda name: None
        # The last phone paired and when: the pairing window watches this and closes itself.
        self.last_paired: tuple[float, str] = (0.0, "")

    def start(self) -> str:
        with self.lock:
            self.secret = secrets.token_bytes(32)
            self.until = time.time() + PAIR_WINDOW_S
            secret = base64.urlsafe_b64encode(self.secret).decode().rstrip("=")
        ips = ",".join(local_ips())
        name = re.sub(r"[^A-Za-z0-9 _.-]", "", PC_NAME)[:40]
        return f"jarvislink:{VERSION}:{AGENT_ID}:{secret}:{PORT}:{ips}:{name}"

    def stop(self):
        with self.lock:
            self.secret = None

    def take(self) -> bytes | None:
        with self.lock:
            if self.secret is None or time.time() > self.until:
                return None
            return self.secret


PAIRING = Pairing()


def handle_pair(req: dict) -> dict:
    secret = PAIRING.take()
    if secret is None:
        return {"ok": False, "error": "No pairing code is showing on the PC. Choose Pair a phone in the JARVIS Link tray menu."}
    try:
        body, _ = open_box(secret, req.get("box", ""), b"pair:" + AGENT_ID.encode())
    except Exception:
        return {"ok": False, "error": "That pairing code doesn't match. Scan the one on the PC again."}
    device = str(body.get("device", ""))[:64]
    key_b64 = str(body.get("key", ""))
    try:
        key = base64.b64decode(key_b64)
    except Exception:
        key = b""
    if not device or len(key) != 32 or abs(time.time() - float(body.get("ts", 0)) / 1000) > MAX_SKEW_S:
        return {"ok": False, "error": "The pairing request was malformed or too old."}
    name = str(body.get("name", "Phone"))[:60]
    p = paired()
    p[device] = {"name": name, "key": key_b64, "paired_at": int(time.time()), "last_seen": int(time.time())}
    save_paired(p)
    PAIRING.stop()
    PAIRING.last_paired = (time.time(), name)
    log.info("paired with %s (%s)", name, device[:8])
    try:
        PAIRING.on_paired(name)
    except Exception:
        log.exception("after-pairing notice failed")
    return {"ok": True, "box": seal(key, {"id": AGENT_ID, "name": PC_NAME}, b"reply:" + device.encode())}


def handle_cmd(req: dict) -> dict:
    device = str(req.get("device", ""))
    entry = paired().get(device)
    if not entry:
        return {"ok": False, "error": "not paired"}
    key = base64.b64decode(entry["key"])
    try:
        body, nonce = open_box(key, req.get("box", ""), b"cmd:" + device.encode())
    except Exception:
        log.warning("a request from %s failed to decrypt", device[:8])
        return {"ok": False, "error": "not paired"}
    if abs(time.time() - float(body.get("ts", 0)) / 1000) > MAX_SKEW_S or not REPLAYS.fresh(nonce):
        return {"ok": False, "box": seal(key, {"ok": False, "text": "The request was too old; the phone's and PC's clocks may differ."}, b"reply:" + device.encode())}
    action = str(body.get("action", ""))
    args = body.get("args") or {}
    if action == "unpair":
        # The phone forgot this PC: forget the phone too, so the pairing is gone on both sides.
        p = paired()
        p.pop(device, None)
        save_paired(p)
        log.info("%s unpaired itself", entry.get("name", "?"))
        return {"ok": True, "box": seal(key, {"ok": True, "text": "Forgotten on the PC too.", "data": None}, b"reply:" + device.encode())}
    fn = ACTIONS.get(action)
    try:
        ok, text, data = fn(args) if fn else (False, f"The PC doesn't know how to {action}.", None)
    except Exception as e:  # an action failing must never take the link down
        log.exception("action %s failed", action)
        ok, text, data = False, f"That failed on the PC: {e.__class__.__name__}.", None
    log.info("%s from %s: %s", action, entry.get("name", "?"), "ok" if ok else "failed")
    p = paired()
    if device in p:
        p[device]["last_seen"] = int(time.time())
        save_paired(p)
    return {"ok": True, "box": seal(key, {"ok": ok, "text": text, "data": data}, b"reply:" + device.encode())}


# ---------------------------------------------------------------------------------------------- actions

def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", s.lower())


def best_match(query: str, names: list[str]) -> tuple[str | None, list[str]]:
    """The name [query] means, or None with the close candidates when it's unclear."""
    q = _norm(query)
    if not q:
        return None, []
    exact = [n for n in names if _norm(n) == q]
    if len(exact) == 1:
        return exact[0], []
    starts = [n for n in names if _norm(n).startswith(q)]
    if len(starts) == 1:
        return starts[0], []
    contains = [n for n in names if q in _norm(n)]
    if len(contains) == 1:
        return contains[0], []
    pool = exact or starts or contains
    if pool:
        return None, pool[:6]
    close = difflib.get_close_matches(q, {_norm(n): n for n in names}.keys(), n=3, cutoff=0.6)
    lookup = {_norm(n): n for n in names}
    if len(close) == 1:
        return lookup[close[0]], []
    return None, [lookup[c] for c in close]


class Project:
    """A project folder: its name, which workspace it's in ("Abhi", "RateUp"), and where it is."""

    def __init__(self, name: str, workspace: str, path: str):
        self.name, self.workspace, self.path = name, workspace, path

    @property
    def full(self) -> str:
        return f"{self.workspace} {self.name}" if self.workspace else self.name


def workspaces() -> dict[str, str]:
    """Named project folders from config.json ("Abhi", "RateUp"); older unnamed roots too, named after their folder."""
    named = dict(CONFIG.get("workspaces", {}))
    for root in CONFIG.get("project_roots", []):
        if root not in named.values():
            named[Path(root).name] = root
    return named


_projects_cache: tuple[float, list] = (0.0, [])


def all_projects() -> list[Project]:
    """Project folders in each workspace (a folder with .git, package.json, …), plus aliases."""
    global _projects_cache
    if time.time() - _projects_cache[0] < 300:
        return _projects_cache[1]
    found: list[Project] = []

    def walk(d: Path, depth: int, workspace: str):
        try:
            entries = list(os.scandir(d))
        except OSError:
            return
        names = {e.name for e in entries}
        if depth > 0 and (names & PROJECT_MARKERS or any(n.endswith(".sln") for n in names)):
            found.append(Project(d.name, workspace, str(d)))
            return
        if depth >= 4:
            return
        for e in entries:
            if e.is_dir(follow_symlinks=False) and e.name not in SKIP_DIRS and not e.name.startswith("."):
                walk(Path(e.path), depth + 1, workspace)

    for label, root in workspaces().items():
        if Path(root).is_dir():
            walk(Path(root), 0, label)
    for alias, path in CONFIG.get("aliases", {}).items():
        if Path(path).is_dir():
            found.append(Project(alias, "", path))
    _projects_cache = (time.time(), found)
    return found


def projects() -> dict[str, str]:
    """Every name a project answers to — its own ("website") and with its workspace ("RateUp website") — to its folder."""
    names: dict[str, str] = {}
    counts: dict[str, int] = {}
    for p in all_projects():
        names.setdefault(p.full, p.path)
        counts[p.name] = counts.get(p.name, 0) + 1
    for p in all_projects():
        if counts[p.name] == 1:
            names.setdefault(p.name, p.path)
    return names


_last_project: str | None = None


def act_list_projects(args):
    groups: dict[str, list[str]] = {}
    for p in all_projects():
        groups.setdefault(p.workspace or "Shortcuts", []).append(p.name)
    if not groups:
        return True, "No projects found. Add your project folders in the JARVIS Link tray menu, Project folders.", []
    text = "; ".join(f"{w}: " + ", ".join(sorted(n, key=str.lower)[:25]) for w, n in groups.items())
    return True, text, {w: sorted(n, key=str.lower) for w, n in groups.items()}


def act_open_project(args):
    global _last_project
    names = projects()
    everything = sorted({p.full for p in all_projects()})
    query = str(args.get("name", "")).strip()
    if not query:
        if _last_project and _last_project in names:
            query = _last_project
        else:
            return False, "Which project? " + ", ".join(everything[:15]), None
    name, options = best_match(query, list(names))
    # "website" found both as itself and as "RateUp website": one folder, so nothing to ask.
    if name is None and options and len({names[o] for o in options}) == 1:
        name = options[0]
    if name is None:
        return False, (f"Which one: {', '.join(options)}?" if options else f"No project called {query}. There are: " + ", ".join(everything[:15])), options
    path = names[name]
    shown = next((p.full for p in all_projects() if p.path == path), name)
    editor = CONFIG.get("editor", "code")
    if editor != "explorer" and shutil.which(editor):
        # shell=True: VS Code's `code` is a .cmd script. The path is quoted and comes from the PC's own folder list.
        subprocess.Popen(f'"{shutil.which(editor)}" "{path}"', shell=True, creationflags=0x08000000)
        how = "VS Code" if editor == "code" else editor
    else:
        os.startfile(path)
        how = "File Explorer"
    _last_project = name
    return True, f"Opened {shown} in {how}.", {"name": shown}


_apps_cache: tuple[float, dict] = (0.0, {})
_apps_lock = threading.Lock()


def start_apps() -> dict[str, str]:
    """
    Every app in the Start menu, by name, to how it's opened — Windows' own list (Get-StartApps), so Microsoft Store
    apps like Spotify and WhatsApp are there too, not only programs with a shortcut file.
    """
    global _apps_cache
    with _apps_lock:
        if time.time() - _apps_cache[0] < 600 and _apps_cache[1]:
            return _apps_cache[1]
        apps: dict[str, str] = {}
        try:
            out = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command",
                 "[Console]::OutputEncoding=[Text.Encoding]::UTF8; Get-StartApps | Select-Object Name,AppID | ConvertTo-Json -Compress"],
                capture_output=True, text=True, encoding="utf-8", timeout=25, creationflags=0x08000000,
            ).stdout
            rows = json.loads(out) if out.strip() else []
            for r in rows if isinstance(rows, list) else [rows]:
                n, app_id = str(r.get("Name", "")).strip(), str(r.get("AppID", "")).strip()
                if n and app_id and not re.search(r"(?i)uninstall|readme|documentation", n):
                    apps.setdefault(n, "app:" + app_id)
        except Exception:
            log.exception("couldn't list the Start menu's apps")
        # Shortcut files as well, for anything that list missed.
        for base in (os.environ.get("PROGRAMDATA", ""), os.environ.get("APPDATA", "")):
            root = Path(base) / "Microsoft/Windows/Start Menu/Programs"
            if root.is_dir():
                for lnk in root.rglob("*.lnk"):
                    if not re.search(r"(?i)uninstall|readme|help|documentation|website", lnk.stem):
                        apps.setdefault(lnk.stem, str(lnk))
        _apps_cache = (time.time(), apps)
        return apps


def act_open_app(args):
    query = str(args.get("name", "")).strip()
    apps = start_apps()
    name, options = best_match(query, list(apps))
    if name is None:
        return False, (f"Which one: {', '.join(options)}?" if options else f"I can't find an app called {query} on the PC."), options
    target = apps[name]
    if target.startswith("app:"):
        # Windows' app id: shell:AppsFolder opens Store apps and desktop programs alike.
        subprocess.Popen(["explorer.exe", "shell:AppsFolder\\" + target[4:]], creationflags=0x08000000)
    else:
        os.startfile(target)
    return True, f"Opened {name}.", {"name": name}


def act_open_url(args):
    url = str(args.get("url", "")).strip()
    if not re.match(r"(?i)^https?://[^\s]+$", url):
        return False, "Only web links (http or https) can be opened on the PC.", None
    webbrowser.open(url)
    return True, "Opened the link on the PC.", None


def act_clipboard(args):
    text = str(args.get("text", ""))[:10_000]
    if not text:
        return False, "Nothing to copy.", None
    subprocess.run(["clip"], input=text.encode("utf-16-le"), check=True, creationflags=0x08000000)
    return True, "Copied to the PC's clipboard.", None


def act_lock(args):
    ctypes.windll.user32.LockWorkStation()
    return True, "Locked the PC.", None


def act_sleep(args):
    # Sleep (or hibernate, if the PC is set to hibernate instead).
    threading.Timer(2.0, lambda: subprocess.run(["rundll32.exe", "powrprof.dll,SetSuspendState", "0,1,0"], creationflags=0x08000000)).start()
    return True, "Putting the PC to sleep.", None


MEDIA_KEYS = {"play_pause": 0xB3, "next": 0xB0, "previous": 0xB1, "stop": 0xB2, "volume_up": 0xAF, "volume_down": 0xAE, "mute": 0xAD}


def act_media(args):
    key = str(args.get("key", "")).lower()
    vk = MEDIA_KEYS.get(key)
    if vk is None:
        return False, "Media keys: " + ", ".join(MEDIA_KEYS), None
    presses = 5 if key in ("volume_up", "volume_down") else 1
    for _ in range(presses):
        ctypes.windll.user32.keybd_event(vk, 0, 0, 0)
        ctypes.windll.user32.keybd_event(vk, 0, 2, 0)
    return True, "Done on the PC.", None


class _Power(ctypes.Structure):
    _fields_ = [("ACLineStatus", ctypes.c_byte), ("BatteryFlag", ctypes.c_byte), ("BatteryLifePercent", ctypes.c_byte),
                ("SystemStatusFlag", ctypes.c_byte), ("BatteryLifeTime", ctypes.c_ulong), ("BatteryFullLifeTime", ctypes.c_ulong)]


def act_status(args):
    s = _Power()
    parts = [f"{PC_NAME} is on"]
    if ctypes.windll.kernel32.GetSystemPowerStatus(ctypes.byref(s)) and s.BatteryFlag != -128 and 0 <= s.BatteryLifePercent <= 100:
        parts.append(f"battery {s.BatteryLifePercent}%" + (", charging" if s.ACLineStatus == 1 else ""))
    return True, ", ".join(parts) + ".", {"name": PC_NAME}


ACTIONS = {
    "status": act_status,
    "list_projects": act_list_projects,
    "open_project": act_open_project,
    "open_app": act_open_app,
    "open_url": act_open_url,
    "clipboard": act_clipboard,
    "lock": act_lock,
    "sleep": act_sleep,
    "media": act_media,
}


# ---------------------------------------------------------------------------------------------- network

def local_ips() -> list[str]:
    """This PC's addresses on the home network (private ranges only)."""
    ips: list[str] = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("192.0.2.1", 9))  # nothing is sent: this only picks the interface a LAN packet would use
        ips.append(s.getsockname()[0])
        s.close()
    except OSError:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ips.append(info[4][0])
    except OSError:
        pass
    private = re.compile(r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)")
    return list(dict.fromkeys(ip for ip in ips if private.match(ip)))


def read_frame(sock: socket.socket) -> dict | None:
    head = _read_exact(sock, 4)
    if head is None:
        return None
    n = struct.unpack(">I", head)[0]
    if n > MAX_FRAME:
        return None
    body = _read_exact(sock, n)
    return json.loads(body.decode("utf-8")) if body is not None else None


def _read_exact(sock: socket.socket, n: int) -> bytes | None:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def write_frame(sock: socket.socket, obj: dict) -> None:
    data = json.dumps(obj).encode("utf-8")
    sock.sendall(struct.pack(">I", len(data)) + data)


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(15)
        peer = self.client_address[0]
        # Home network only: a request from anywhere else is dropped unanswered.
        if not re.match(r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.)", peer):
            return
        try:
            req = read_frame(self.request)
            if not req:
                return
            t = req.get("t")
            if t == "hello":
                reply = {"ok": True, "id": AGENT_ID, "name": PC_NAME, "v": VERSION}
            elif t == "pair":
                reply = handle_pair(req)
            elif t == "cmd":
                reply = handle_cmd(req)
            else:
                reply = {"ok": False, "error": "unknown"}
            write_frame(self.request, reply)
        except Exception:
            log.exception("request from %s failed", peer)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = False
    daemon_threads = True


def advertise():
    """Tells phones on the Wi-Fi where this PC is (mDNS), and keeps it right when the address changes."""
    try:
        from zeroconf import IPVersion, ServiceInfo, Zeroconf
    except ImportError:
        log.warning("zeroconf is not installed: phones will use the address they paired with")
        return
    zc = Zeroconf(ip_version=IPVersion.V4Only)
    info = None
    last: list[str] = []
    while True:
        ips = local_ips()
        if ips != last:
            try:
                if info:
                    zc.unregister_service(info)
                info = ServiceInfo(SERVICE, f"JARVIS Link {AGENT_ID[:8]}.{SERVICE}", port=PORT, parsed_addresses=ips,
                                   properties={"id": AGENT_ID, "name": PC_NAME})
                zc.register_service(info)
                log.info("advertising on %s", ", ".join(ips))
                last = ips
            except Exception:
                log.exception("mDNS registration failed")
        time.sleep(60)


# ---------------------------------------------------------------------------------------------- tray & windows

def start_with_windows(on: bool) -> None:
    if on:
        pythonw = Path(sys.executable).with_name("pythonw.exe")
        exe = str(pythonw if pythonw.exists() else sys.executable)
        script = str(Path(__file__).resolve())
        STARTUP_FILE.write_text(f'CreateObject("WScript.Shell").Run """{exe}"" ""{script}""", 0\n', "utf-8")
    elif STARTUP_FILE.exists():
        STARTUP_FILE.unlink()


def run_ui():
    import tkinter as tk

    import pystray
    import qrcode
    from PIL import Image, ImageDraw, ImageTk

    BG, CARD, TEXT, DIM, ACCENT, RED, GREEN = "#0d1117", "#161b22", "#e6edf3", "#8b949e", "#40c8ff", "#ff6b6b", "#3fb950"
    FONT = "Segoe UI"

    root = tk.Tk()
    root.withdraw()
    jobs: queue.Queue = queue.Queue()
    ui: dict = {"win": None}

    def icon_image():
        img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
        d = ImageDraw.Draw(img)
        d.ellipse((4, 4, 60, 60), outline=(64, 200, 255, 255), width=6)
        d.ellipse((22, 22, 42, 42), fill=(64, 200, 255, 255))
        return img

    def ago(ts: int) -> str:
        s = int(time.time()) - int(ts or 0)
        if s < 90:
            return "just now"
        if s < 3600:
            return f"{s // 60} min ago"
        if s < 86400:
            return f"{s // 3600} h ago"
        return time.strftime("%d %b", time.localtime(ts))

    def show_window(pair_now: bool = False):
        """The one window: this PC's paired phones (forget any), and a QR code to pair another."""
        w = ui.get("win")
        if w is not None and w.winfo_exists():
            w.deiconify()
            w.lift()
            if pair_now:
                ui["start_pairing"]()
            return
        w = tk.Toplevel(root)
        ui["win"] = w
        w.title(f"{APP} — {PC_NAME}")
        w.configure(bg=BG)
        w.resizable(False, False)
        try:
            w.iconphoto(False, ImageTk.PhotoImage(icon_image()))
        except Exception:
            pass

        tk.Label(w, text=APP, bg=BG, fg=TEXT, font=(FONT, 16, "bold")).pack(anchor="w", padx=20, pady=(18, 0))
        tk.Label(w, text=f"Lets JARVIS on your phone use {PC_NAME} over your home Wi-Fi.", bg=BG, fg=DIM,
                 font=(FONT, 10)).pack(anchor="w", padx=20)

        # ------------------------------------------------ paired phones
        tk.Label(w, text="PAIRED PHONES", bg=BG, fg=ACCENT, font=(FONT, 9, "bold")).pack(anchor="w", padx=20, pady=(16, 4))
        phones = tk.Frame(w, bg=CARD, highlightthickness=1, highlightbackground="#30363d")
        phones.pack(fill="x", padx=20)
        shown: dict = {"sig": None}

        def forget(device: str, name: str):
            p = paired()
            p.pop(device, None)
            save_paired(p)
            log.info("removed %s", name)
            draw_phones(force=True)
            try:
                icon.update_menu()
            except Exception:
                pass

        def draw_phones(force: bool = False):
            p = paired()
            sig = json.dumps(p, sort_keys=True)
            if sig == shown["sig"] and not force:
                return
            shown["sig"] = sig
            for child in phones.winfo_children():
                child.destroy()
            if not p:
                tk.Label(phones, text="No phones paired yet. Pair one below.", bg=CARD, fg=DIM, font=(FONT, 10)).pack(anchor="w", padx=14, pady=12)
                return
            for device, v in sorted(p.items(), key=lambda kv: -kv[1].get("last_seen", 0)):
                row = tk.Frame(phones, bg=CARD)
                row.pack(fill="x", padx=14, pady=8)
                recent = int(time.time()) - int(v.get("last_seen", 0)) < 600
                tk.Label(row, text="●", bg=CARD, fg=GREEN if recent else DIM, font=(FONT, 10)).pack(side="left")
                info = tk.Frame(row, bg=CARD)
                info.pack(side="left", padx=(8, 0))
                tk.Label(info, text=v.get("name", "Phone"), bg=CARD, fg=TEXT, font=(FONT, 11)).pack(anchor="w")
                tk.Label(info, text=f"Last used {ago(v.get('last_seen', 0))} · paired {ago(v.get('paired_at', 0))}",
                         bg=CARD, fg=DIM, font=(FONT, 9)).pack(anchor="w")
                tk.Button(row, text="Forget", command=lambda d=device, n=v.get("name", "phone"): forget(d, n),
                          bg=CARD, fg=RED, activebackground=CARD, activeforeground=RED, relief="flat", bd=0,
                          font=(FONT, 10), cursor="hand2").pack(side="right")

        # ------------------------------------------------ pairing
        tk.Label(w, text="PAIR A PHONE", bg=BG, fg=ACCENT, font=(FONT, 9, "bold")).pack(anchor="w", padx=20, pady=(16, 4))
        pair = tk.Frame(w, bg=CARD, highlightthickness=1, highlightbackground="#30363d")
        pair.pack(fill="x", padx=20, pady=(0, 20))
        qr_label = tk.Label(pair, bg=CARD)
        note = tk.Label(pair, bg=CARD, fg=DIM, font=(FONT, 10), justify="left", wraplength=340)
        note.pack(anchor="w", padx=14, pady=(12, 6))
        button = tk.Button(pair, bg=ACCENT, fg="#00131c", activebackground=ACCENT, relief="flat", bd=0,
                           font=(FONT, 10, "bold"), padx=14, pady=6, cursor="hand2")
        button.pack(anchor="w", padx=14, pady=(0, 14))
        state = {"opened": 0.0, "until": 0.0, "photo": None}

        def idle(message: str | None = None, color: str = DIM):
            qr_label.pack_forget()
            note.config(text=message or "On your phone: JARVIS → Settings → Abilities → PC link → Scan the laptop's code.", fg=color)
            button.config(text="Show QR code", command=start_pairing)
            state["until"] = 0.0

        def start_pairing():
            code = PAIRING.start()
            qr = qrcode.QRCode(border=2, box_size=7)
            qr.add_data(code)
            qr.make(fit=True)
            state["photo"] = ImageTk.PhotoImage(qr.make_image(fill_color="black", back_color="white").convert("RGB"))
            qr_label.config(image=state["photo"])
            qr_label.pack(before=note, padx=14, pady=(14, 0))
            state["opened"] = time.time()
            state["until"] = state["opened"] + PAIR_WINDOW_S
            button.config(text="New code", command=start_pairing)

        ui["start_pairing"] = start_pairing

        def tick():
            if not w.winfo_exists():
                return
            draw_phones()
            if state["until"]:
                at, who = PAIRING.last_paired
                left = int(state["until"] - time.time())
                if at >= state["opened"]:
                    idle(f"Paired with {who}. ✓", GREEN)
                elif left <= 0:
                    PAIRING.stop()
                    idle("That code expired. Show a new one when you're ready.")
                else:
                    note.config(text=f"Scan this with JARVIS on your phone: Settings → Abilities → PC link. "
                                     f"Works once, for {left // 60}:{left % 60:02d}. Same Wi-Fi only.", fg=DIM)
            w.after(1000, tick)

        def close():
            PAIRING.stop()
            w.destroy()

        w.protocol("WM_DELETE_WINDOW", close)
        idle()
        draw_phones(force=True)
        if pair_now:
            start_pairing()
        tick()
        w.update_idletasks()
        w.geometry(f"+{(w.winfo_screenwidth() - w.winfo_width()) // 2}+{(w.winfo_screenheight() - w.winfo_height()) // 3}")
        w.lift()
        w.focus_force()

    def paired_done(name):
        def note():
            try:
                icon.notify(f"Paired with {name}. JARVIS on that phone can now use this PC.", APP)
            except Exception:
                log.exception("tray notice failed")
        jobs.put(note)

    PAIRING.on_paired = paired_done

    def toggle_startup(icon_, item):
        start_with_windows(not STARTUP_FILE.exists())

    def quit_(icon_, item):
        icon.stop()
        jobs.put(root.destroy)

    icon = pystray.Icon(
        "jarvis_link", icon_image(), APP,
        menu=pystray.Menu(
            pystray.MenuItem("Open JARVIS Link", lambda i, it: jobs.put(show_window), default=True),
            pystray.MenuItem("Pair a phone…", lambda i, it: jobs.put(lambda: show_window(pair_now=True))),
            pystray.MenuItem("Project folders…", lambda i, it: os.startfile(CONFIG_FILE)),
            pystray.MenuItem("Start with Windows", toggle_startup, checked=lambda item: STARTUP_FILE.exists()),
            pystray.MenuItem("Open log", lambda i, it: os.startfile(LOG_FILE)),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Quit", quit_),
        ),
    )
    icon.run_detached()

    def pump():
        while True:
            try:
                jobs.get_nowait()()
            except queue.Empty:
                break
            except Exception:
                log.exception("tray job failed")
        root.after(200, pump)

    pump()
    if not paired():
        root.after(800, lambda: show_window(pair_now=True))
    root.mainloop()


def already_running() -> bool:
    ctypes.windll.user32.MessageBoxW(None, f"{APP} is already running (look in the system tray).", APP, 0x40)
    return True


def main():
    try:
        server = Server(("0.0.0.0", PORT), Handler)
    except OSError:
        already_running()
        return
    threading.Thread(target=server.serve_forever, daemon=True).start()
    threading.Thread(target=advertise, daemon=True).start()
    threading.Thread(target=start_apps, daemon=True).start()  # so the first "open …" needn't wait for it
    log.info("%s listening on port %d (%s)", APP, PORT, ", ".join(local_ips()))
    if "--headless" in sys.argv:
        threading.Event().wait()
    else:
        run_ui()
    server.shutdown()


if __name__ == "__main__":
    main()
