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
MAX_FRAME = 1536 * 1024       # a file arrives in pieces of 384 KB; anything bigger is refused
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


KNOWN_FOLDERS = {
    "Downloads": "{374DE290-123F-4565-9164-39C4925E467B}",
    "Desktop": "{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}",
    "Documents": "{FDD39AD0-238F-46AF-ADB4-6C85480369C7}",
    "Pictures": "{33E28130-4E1E-4676-835A-98395C3BC3BB}",
    "Screenshots": "{B7BEDE81-DF94-4682-A7D8-57A52620B86F}",
}


def known_folder(name: str) -> Path | None:
    """Where Windows really keeps Downloads, Desktop, Pictures… — OneDrive moves some of them."""
    guid = KNOWN_FOLDERS.get(name)
    if guid:
        try:
            class GUID(ctypes.Structure):
                _fields_ = [("a", ctypes.c_uint32), ("b", ctypes.c_uint16), ("c", ctypes.c_uint16), ("d", ctypes.c_ubyte * 8)]
            g = GUID()
            ctypes.windll.ole32.CLSIDFromString(ctypes.c_wchar_p(guid), ctypes.byref(g))
            out = ctypes.c_wchar_p()
            if ctypes.windll.shell32.SHGetKnownFolderPath(ctypes.byref(g), 0, None, ctypes.byref(out)) == 0:
                path = Path(out.value)
                ctypes.windll.ole32.CoTaskMemFree(out)
                if path.is_dir():
                    return path
        except Exception:
            pass
    fallback = Path.home() / ("Pictures/Screenshots" if name == "Screenshots" else name)
    return fallback if fallback.is_dir() else None


def default_share_folders() -> dict[str, str]:
    found = {n: known_folder(n) for n in KNOWN_FOLDERS}
    return {n: str(v) for n, v in found.items() if v}


def load_config() -> dict:
    c = _load(CONFIG_FILE, {})
    changed = False
    if "id" not in c:
        c["id"] = uuid.uuid4().hex
        changed = True
    if "workspaces" not in c and "project_roots" not in c:
        # Named project folders: "open the RateUp website" picks the website in RateUp. Edit in Settings (folders)….
        home = Path.home()
        guesses = [home / "Documents", home / "Projects", home / "source" / "repos", home / "StudioProjects"]
        c["workspaces"] = {p.name: str(p) for p in guesses if p.is_dir()}
        changed = True
    if "share_folders" not in c:
        c["share_folders"] = default_share_folders()
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
        self._pruned = 0.0

    def fresh(self, nonce: bytes) -> bool:
        now = time.time()
        with self._lock:
            if now - self._pruned > 1:
                self._pruned = now
                for n, t in list(self._seen.items()):
                    if now - t > MAX_SKEW_S * 2:
                        del self._seen[n]
            if nonce in self._seen:
                return False
            self._seen[nonce] = now
            return True


REPLAYS = Replays()

# Many to a second, or one piece of a file: not written to the log one by one.
QUIET_ACTIONS = {"file_chunk", "file_get_chunk", "pointer", "key", "agents_wait"}
_last_seen_saved: dict[str, int] = {}


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
    if action not in QUIET_ACTIONS:
        log.info("%s from %s: %s", action, entry.get("name", "?"), "ok" if ok else "failed")
    now = int(time.time())
    if now - _last_seen_saved.get(device, 0) > 60:
        _last_seen_saved[device] = now
        p = paired()
        if device in p:
            p[device]["last_seen"] = now
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
        return True, "No projects found. Add your project folders in the JARVIS Link tray menu, Settings (folders).", []
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


MAX_CLIP = 20_000


def act_clipboard(args):
    text = str(args.get("text", ""))[:10_000]
    if not text:
        return False, "Nothing to copy.", None
    subprocess.run(["clip"], input=text.encode("utf-16-le"), check=True, creationflags=0x08000000)
    return True, "Copied to the PC's clipboard.", None


def act_clipboard_get(args):
    """The text on the PC's clipboard (not pictures or files), for the phone's clipboard."""
    k32 = ctypes.windll.kernel32
    k32.GlobalLock.restype = ctypes.c_void_p
    k32.GlobalLock.argtypes = [ctypes.c_void_p]
    k32.GlobalUnlock.argtypes = [ctypes.c_void_p]
    _u32.GetClipboardData.restype = ctypes.c_void_p
    text = None
    for _ in range(5):  # another app may have it open for a moment
        if _u32.OpenClipboard(None):
            break
        time.sleep(0.05)
    else:
        return False, "The PC's clipboard is busy; try again.", None
    try:
        h = _u32.GetClipboardData(13)  # CF_UNICODETEXT
        if h:
            ptr = k32.GlobalLock(h)
            if ptr:
                try:
                    text = ctypes.wstring_at(ptr)
                finally:
                    k32.GlobalUnlock(h)
    finally:
        _u32.CloseClipboard()
    if not text:
        return False, f"There's no text copied on {PC_NAME}.", None
    return True, f"Took {len(text)} characters from {PC_NAME}'s clipboard.", {"text": text[:MAX_CLIP]}


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
    # Memory and the system drive's space too (both instant), so "how's my laptop?" gets the numbers either way.
    try:
        m = _MemStatus()
        m.dwLength = ctypes.sizeof(m)
        if _k32.GlobalMemoryStatusEx(ctypes.byref(m)):
            parts.append(f"memory {_gb(m.ullTotalPhys - m.ullAvailPhys)} of {_gb(m.ullTotalPhys)} in use")
        system = os.environ.get("SystemDrive", "C:")
        u = shutil.disk_usage(system + "\\")
        parts.append(f"{system} {_gb(u.free)} free of {_gb(u.total)}")
    except Exception:
        pass
    return True, ", ".join(parts) + ".", {"name": PC_NAME}


# ---------------------------------------------------------------------------------------------- how the PC is doing
# Read-only: how busy it is, disk space, which apps are open (names only, never window titles), and downloads.
# Windows' own functions through ctypes, so no extra packages.

from ctypes import wintypes

_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
_u32 = ctypes.WinDLL("user32", use_last_error=True)
_k32.OpenProcess.restype = wintypes.HANDLE
_k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
_k32.CloseHandle.argtypes = [wintypes.HANDLE]
_k32.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
_k32.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
_k32.K32GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD]
_k32.K32EnumProcesses.argtypes = [ctypes.POINTER(wintypes.DWORD), wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
_u32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
_u32.GetWindow.restype = wintypes.HWND
_u32.GetWindow.argtypes = [wintypes.HWND, wintypes.UINT]
_u32.GetWindowLongW.argtypes = [wintypes.HWND, ctypes.c_int]
_u32.IsWindowVisible.argtypes = [wintypes.HWND]
_u32.GetWindowTextLengthW.argtypes = [wintypes.HWND]
_u32.GetClassNameW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
_WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
_u32.EnumWindows.argtypes = [_WNDENUMPROC, wintypes.LPARAM]
_u32.EnumChildWindows.argtypes = [wintypes.HWND, _WNDENUMPROC, wintypes.LPARAM]

_QUERY_LIMITED = 0x1000


class _MemStatus(ctypes.Structure):
    _fields_ = [("dwLength", wintypes.DWORD), ("dwMemoryLoad", wintypes.DWORD), ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong), ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong), ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong), ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]


class _ProcMem(ctypes.Structure):
    _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD), ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t), ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t), ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t), ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t)]


def _ft(f: wintypes.FILETIME) -> int:
    return (f.dwHighDateTime << 32) | f.dwLowDateTime


def _gb(n: float) -> str:
    g = n / 1024 ** 3
    return f"{g:.1f} GB" if g < 10 else f"{g:.0f} GB"


def _pids() -> list[int]:
    arr = (wintypes.DWORD * 4096)()
    got = wintypes.DWORD()
    if not _k32.K32EnumProcesses(arr, ctypes.sizeof(arr), ctypes.byref(got)):
        return []
    return [p for p in arr[: got.value // ctypes.sizeof(wintypes.DWORD)] if p]


def _exe(handle) -> str | None:
    buf = ctypes.create_unicode_buffer(1024)
    n = wintypes.DWORD(len(buf))
    return buf.value if _k32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(n)) else None


def _exe_of(pid: int) -> str | None:
    h = _k32.OpenProcess(_QUERY_LIMITED, False, pid)
    if not h:
        return None
    try:
        return _exe(h)
    finally:
        _k32.CloseHandle(h)


_app_names: dict[str, str] = {}
_NAME_FIXES = {"Windows Explorer": "File Explorer", "Code": "VS Code", "Visual Studio Code": "VS Code",
               "OpenJDK Platform binary": "Java", "Java(TM) Platform SE binary": "Java"}


def app_name(exe: str) -> str:
    """What people call a program: its own description ("Google Chrome"), else its file name ("chrome")."""
    if exe in _app_names:
        return _app_names[exe]
    name = Path(exe).stem
    try:
        ver = ctypes.WinDLL("version")
        size = ver.GetFileVersionInfoSizeW(exe, None)
        if size:
            data = ctypes.create_string_buffer(size)
            if ver.GetFileVersionInfoW(exe, 0, size, data):
                ptr, n = ctypes.c_void_p(), wintypes.UINT()
                if ver.VerQueryValueW(data, "\\VarFileInfo\\Translation", ctypes.byref(ptr), ctypes.byref(n)) and n.value >= 4:
                    lang, cp = ctypes.cast(ptr, ctypes.POINTER(ctypes.c_ushort * 2)).contents
                    key = f"\\StringFileInfo\\{lang:04x}{cp:04x}\\FileDescription"
                    if ver.VerQueryValueW(data, key, ctypes.byref(ptr), ctypes.byref(n)) and n.value > 1:
                        desc = ctypes.wstring_at(ptr, n.value - 1).strip()
                        if 1 < len(desc) <= 40:
                            name = desc
    except Exception:
        pass
    name = _NAME_FIXES.get(name, name)
    _app_names[exe] = name
    return name


def _processes() -> dict[int, tuple[str, int, int]]:
    """Every process this user can see: pid → (program, CPU time so far, memory in use)."""
    out = {}
    for pid in _pids():
        h = _k32.OpenProcess(_QUERY_LIMITED, False, pid)
        if not h:
            continue
        try:
            exe = _exe(h)
            if not exe:
                continue
            c, e, k, u = (wintypes.FILETIME() for _ in range(4))
            cpu = _ft(k) + _ft(u) if _k32.GetProcessTimes(h, ctypes.byref(c), ctypes.byref(e), ctypes.byref(k), ctypes.byref(u)) else 0
            mem = _ProcMem()
            mem.cb = ctypes.sizeof(mem)
            ram = mem.WorkingSetSize if _k32.K32GetProcessMemoryInfo(h, ctypes.byref(mem), mem.cb) else 0
            out[pid] = (exe, cpu, ram)
        finally:
            _k32.CloseHandle(h)
    return out


_SKIP_PROGRAMS = {"system", "registry", "memory compression", "idle", "secure system"}


def act_usage(args):
    """How busy the PC is: CPU and memory, and which programs use the most of each (a one-second look)."""
    idle0, kern0, user0 = wintypes.FILETIME(), wintypes.FILETIME(), wintypes.FILETIME()
    _k32.GetSystemTimes(ctypes.byref(idle0), ctypes.byref(kern0), ctypes.byref(user0))
    before, t0 = _processes(), time.perf_counter()
    time.sleep(1.0)
    idle1, kern1, user1 = wintypes.FILETIME(), wintypes.FILETIME(), wintypes.FILETIME()
    _k32.GetSystemTimes(ctypes.byref(idle1), ctypes.byref(kern1), ctypes.byref(user1))
    after, t1 = _processes(), time.perf_counter()

    busy_all = (_ft(kern1) - _ft(kern0)) + (_ft(user1) - _ft(user0))
    cpu = max(0.0, min(100.0, 100.0 * (1 - (_ft(idle1) - _ft(idle0)) / busy_all))) if busy_all else 0.0
    m = _MemStatus()
    m.dwLength = ctypes.sizeof(m)
    _k32.GlobalMemoryStatusEx(ctypes.byref(m))
    used = m.ullTotalPhys - m.ullAvailPhys

    cores = os.cpu_count() or 1
    by_cpu: dict[str, float] = {}
    by_ram: dict[str, int] = {}
    for pid, (exe, t, ram) in after.items():
        name = app_name(exe)
        if name.lower() in _SKIP_PROGRAMS or Path(exe).name.lower() == "pythonw.exe" and pid == os.getpid():
            continue
        if pid in before and before[pid][0] == exe:
            by_cpu[name] = by_cpu.get(name, 0.0) + (t - before[pid][1]) / 1e7 / (t1 - t0) / cores * 100
        by_ram[name] = by_ram.get(name, 0) + ram
    top_cpu = sorted(((v, k) for k, v in by_cpu.items() if v >= 1), reverse=True)[:3]
    top_ram = sorted(((v, k) for k, v in by_ram.items()), reverse=True)[:3]

    parts = [f"CPU {cpu:.0f}%", f"memory {_gb(used)} of {_gb(m.ullTotalPhys)} in use ({m.dwMemoryLoad}%)"]
    text = f"{PC_NAME}: " + ", ".join(parts) + "."
    if top_cpu:
        text += " Busiest: " + ", ".join(f"{n} {v:.0f}%" for v, n in top_cpu) + "."
    else:
        text += " Nothing is working hard."
    if top_ram:
        text += " Most memory: " + ", ".join(f"{n} {_gb(v)}" for v, n in top_ram) + "."
    return True, text, {
        "cpu": round(cpu), "ram_used": used, "ram_total": m.ullTotalPhys,
        "top_cpu": [{"name": n, "percent": round(v)} for v, n in top_cpu],
        "top_ram": [{"name": n, "bytes": v} for v, n in top_ram],
    }


def act_disk(args):
    """Free space on each of the PC's own drives (not USB sticks or network drives)."""
    drives = []
    mask = _k32.GetLogicalDrives()
    for i in range(26):
        if not mask & (1 << i):
            continue
        root = f"{chr(65 + i)}:\\"
        if _k32.GetDriveTypeW(root) != 3:  # DRIVE_FIXED
            continue
        try:
            u = shutil.disk_usage(root)
        except OSError:
            continue
        drives.append({"drive": root[:2], "free": u.free, "total": u.total})
    if not drives:
        return False, "I couldn't read the PC's drives.", None
    lines = [f"{d['drive']} {_gb(d['free'])} free of {_gb(d['total'])}" for d in drives]
    low = [d["drive"] for d in drives if d["free"] < 0.1 * d["total"]]
    text = f"{PC_NAME}: " + "; ".join(lines) + "."
    if low:
        text += " " + " and ".join(low) + (" is" if len(low) == 1 else " are") + " nearly full."
    return True, text, {"drives": drives}


_SHELL_CLASSES = {"Progman", "WorkerW", "Shell_TrayWnd", "Shell_SecondaryTrayWnd"}


def open_apps() -> dict[str, int]:
    """The programs with a window open on the desktop (minimised ones too), and how many windows each: names only."""
    found: dict[str, int] = {}
    for name, _ in app_windows():
        found[name] = found.get(name, 0) + 1
    return found


def app_windows() -> list[tuple[str, int]]:
    """Each app window on the desktop (minimised ones too), front-most first, with its program's name."""
    dwm = ctypes.WinDLL("dwmapi")
    found: list[tuple[str, int]] = []
    me = os.getpid()

    def pid_of(hwnd) -> int:
        pid = wintypes.DWORD()
        _u32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        return pid.value

    def on_window(hwnd, _):
        try:
            if not _u32.IsWindowVisible(hwnd) or _u32.GetWindow(hwnd, 4) or not _u32.GetWindowTextLengthW(hwnd):
                return True  # hidden, owned by another window (a dialog), or untitled
            if _u32.GetWindowLongW(hwnd, -20) & 0x80:  # WS_EX_TOOLWINDOW
                return True
            cloaked = wintypes.DWORD()
            if dwm.DwmGetWindowAttribute(hwnd, 14, ctypes.byref(cloaked), 4) == 0 and cloaked.value:
                return True  # a Store app that isn't really showing
            cls = ctypes.create_unicode_buffer(64)
            _u32.GetClassNameW(hwnd, cls, 64)
            if cls.value in _SHELL_CLASSES:
                return True
            pid = pid_of(hwnd)
            if pid == me:
                return True
            exe = _exe_of(pid)
            if exe and Path(exe).name.lower() == "applicationframehost.exe":
                # A Store app's frame: the app itself is the child window from another process.
                inner = []

                def on_child(child, _):
                    cp = pid_of(child)
                    if cp != pid:
                        inner.append(cp)
                        return False
                    return True

                _u32.EnumChildWindows(hwnd, _WNDENUMPROC(on_child), 0)
                exe = _exe_of(inner[0]) if inner else None
            if exe:
                found.append((app_name(exe), int(hwnd)))
        except Exception:
            pass
        return True

    _u32.EnumWindows(_WNDENUMPROC(on_window), 0)
    return found


def act_open_apps(args):
    apps = open_apps()
    if not apps:
        return True, f"No apps are open on {PC_NAME}.", {"apps": []}
    names = sorted(apps, key=str.lower)
    said = [f"{n} ({apps[n]} windows)" if apps[n] > 1 else n for n in names]
    return True, f"Open on {PC_NAME}: " + ", ".join(said) + ".", {"apps": [{"name": n, "windows": apps[n]} for n in names]}


def _windows_of(query: str) -> tuple[str | None, list[int], list[str]]:
    """The app [query] means, among those with a window open, and its windows; else the open apps' names."""
    wins = app_windows()
    names = list(dict.fromkeys(n for n, _ in wins))
    name, _ = best_match(query, names)
    return name, [h for n, h in wins if n == name], names


def act_close_app(args):
    """Closes an app's windows the way the X button does: apps with unsaved work still ask. Never forced."""
    query = str(args.get("name", "")).strip()
    if not query:
        return False, "Which app should I close?", None
    name, hwnds, names = _windows_of(query)
    if not name:
        return False, f"{query} isn't open on {PC_NAME}. Open: " + (", ".join(sorted(names, key=str.lower)) or "nothing") + ".", None
    for h in hwnds:
        _u32.PostMessageW(wintypes.HWND(h), 0x0010, 0, 0)  # WM_CLOSE
    return True, f"Closing {name} on {PC_NAME}" + (f" ({len(hwnds)} windows)" if len(hwnds) > 1 else "") + ". If it has unsaved work, it will ask there.", {"app": name}


def act_switch_to(args):
    """Brings an open app's window to the front (restoring it if minimised)."""
    query = str(args.get("name", "")).strip()
    if not query:
        return False, "Which app should I switch to?", None
    name, hwnds, names = _windows_of(query)
    if not name:
        return False, f"{query} isn't open on {PC_NAME}. Open: " + (", ".join(sorted(names, key=str.lower)) or "nothing") + ".", None
    h = wintypes.HWND(hwnds[0])
    if _u32.IsIconic(h):
        _u32.ShowWindow(h, 9)  # SW_RESTORE
    # Windows only lets the app the user last used take the front; a tap of Alt counts as using this one.
    _keys([(0x12, 0, 0), (0x12, 0, 2)])
    _u32.SetForegroundWindow(h)
    return True, f"Switched to {name} on {PC_NAME}.", {"app": name}


def act_show_desktop(args):
    """Win+D: everything out of the way, and back again the second time."""
    _keys([(0x5B, 0, 0), (0x44, 0, 0), (0x44, 0, 2), (0x5B, 0, 2)])
    return True, f"Showing the desktop on {PC_NAME} (say it again to bring the windows back).", None


# Browsers' unfinished downloads: Chrome/Edge .crdownload, Firefox .part, old Edge .partial, Opera .opdownload.
_PARTIAL = {".crdownload", ".part", ".partial", ".opdownload", ".download"}


def act_downloads(args):
    """What's still downloading in Downloads (and whether it's moving), and what finished lately."""
    folder = known_folder("Downloads") or Path.home() / "Downloads"
    if not folder.is_dir():
        return False, "I can't find the Downloads folder.", None
    partial, done = [], []
    for f in folder.iterdir():
        try:
            if not f.is_file() or f.name.startswith("."):
                continue
            st = f.stat()
        except OSError:
            continue
        if f.suffix.lower() in _PARTIAL:
            partial.append((f, st.st_size))
        elif time.time() - st.st_mtime < 3 * 3600 and st.st_size > 0:
            done.append((st.st_mtime, f.name, st.st_size))
    growing = set()
    if partial:
        time.sleep(1.5)
        for f, size in partial:
            try:
                if f.stat().st_size != size:
                    growing.add(f)
            except OSError:
                growing.add(f)  # gone: it just finished
    parts, data = [], {"downloading": [], "finished": []}
    for f, size in partial[:5]:
        real = f.stem
        if real.lower().startswith("unconfirmed "):
            real = "a file"
        state = "downloading" if f in growing else "not moving (paused or stuck)"
        parts.append(f"{real}: {state}, {_size(size)} so far")
        data["downloading"].append({"name": real, "bytes": size, "moving": f in growing})
    done.sort(reverse=True)
    if partial:
        text = "Still downloading on the PC: " + "; ".join(parts) + "."
    else:
        text = "Nothing is downloading on the PC."
    if done:
        at, name, size = done[0]
        text += f" Latest finished: {name} ({_size(size)}) at {time.strftime('%H:%M', time.localtime(at))}."
        data["finished"] = [{"name": n, "bytes": b, "at": int(t * 1000)} for t, n, b in done[:5]]
    elif not partial:
        text += " Nothing finished in the last 3 hours."
    return True, text, data


# ---------------------------------------------------------------------------------------------- control
# Volume and brightness to a level, screen off, shutdown / restart (with time to cancel), and typing words.
# The phone asks the user before shutdown, restart, and typing that presses Enter.

on_notice = lambda text: None  # a tray notice on the PC, set by the UI


def _level(args) -> int | None:
    try:
        return max(0, min(100, int(round(float(str(args.get("level", "")).strip().rstrip("%"))))))
    except ValueError:
        return None


class _GUID(ctypes.Structure):
    _fields_ = [("a", wintypes.DWORD), ("b", wintypes.WORD), ("c", wintypes.WORD), ("d", ctypes.c_ubyte * 8)]

    def __init__(self, text: str):
        super().__init__()
        ctypes.oledll.ole32.CLSIDFromString(text, ctypes.byref(self))


def _com(obj, index: int, *types):
    """Method [index] of a COM object's table, callable with the object first."""
    table = ctypes.cast(obj, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))).contents
    return ctypes.WINFUNCTYPE(ctypes.HRESULT, ctypes.c_void_p, *types)(table[index])


def _release(obj):
    if obj:
        ctypes.WINFUNCTYPE(ctypes.c_ulong, ctypes.c_void_p)(ctypes.cast(obj, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))).contents[2])(obj)


def _speakers(use):
    """Runs use(volume) with the default speakers' IAudioEndpointVolume (Windows Core Audio, no packages)."""
    ole = ctypes.oledll.ole32
    started = ctypes.windll.ole32.CoInitializeEx(None, 0) in (0, 1)  # S_OK / S_FALSE: this thread is ours to close
    enum = dev = vol = None
    try:
        enum = ctypes.c_void_p()
        ole.CoCreateInstance(ctypes.byref(_GUID("{BCDE0395-E52F-467C-8E3D-C4579291692E}")), None, 1,
                             ctypes.byref(_GUID("{A95664D2-9614-4F35-A746-DE8DB63617E6}")), ctypes.byref(enum))
        dev = ctypes.c_void_p()
        _com(enum, 4, ctypes.c_int, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p))(enum, 0, 1, ctypes.byref(dev))  # render, multimedia
        vol = ctypes.c_void_p()
        iid = _GUID("{5CDF2C82-841E-4546-9722-0CF74078229A}")  # IAudioEndpointVolume
        _com(dev, 3, ctypes.POINTER(_GUID), wintypes.DWORD, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p))(
            dev, ctypes.byref(iid), 23, None, ctypes.byref(vol))
        return use(vol)
    finally:
        for o in (vol, dev, enum):
            _release(o)
        if started:
            ctypes.windll.ole32.CoUninitialize()


def _get_volume(vol) -> tuple[int, bool]:
    level, muted = ctypes.c_float(), wintypes.BOOL()
    _com(vol, 9, ctypes.POINTER(ctypes.c_float))(vol, ctypes.byref(level))
    _com(vol, 15, ctypes.POINTER(wintypes.BOOL))(vol, ctypes.byref(muted))
    return round(level.value * 100), bool(muted.value)


def act_volume(args):
    """The PC's volume: set to a level (0–100), mute or unmute, or just say what it is."""
    level = _level(args)
    mute = str(args.get("mute", "")).lower()

    def use(vol):
        if level is not None:
            _com(vol, 7, ctypes.c_float, ctypes.c_void_p)(vol, level / 100, None)
            _com(vol, 14, wintypes.BOOL, ctypes.c_void_p)(vol, False, None)
        if mute in ("true", "false"):
            _com(vol, 14, wintypes.BOOL, ctypes.c_void_p)(vol, mute == "true", None)
        return _get_volume(vol)

    try:
        now, muted = _speakers(use)
    except OSError:
        return False, "This PC has no speakers I can reach.", None
    if muted:
        return True, f"{PC_NAME}'s sound is muted (volume {now}%).", {"level": now, "muted": True}
    # "is now" only when it was changed: a reply that just reads it out must not sound like it was set.
    return True, f"{PC_NAME}'s volume is {'now ' if level is not None else ''}{now}%.", {"level": now, "muted": False}


def _powershell(script: str, timeout: float = 15) -> subprocess.CompletedProcess:
    return subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                          capture_output=True, text=True, timeout=timeout, creationflags=0x08000000)


def act_brightness(args):
    """The built-in screen's brightness (a laptop's own panel; separate monitors have their own buttons)."""
    level = _level(args)
    if level is not None:
        r = _powershell("Get-CimInstance -Namespace root/WMI -ClassName WmiMonitorBrightnessMethods -ErrorAction Stop | "
                        f"Invoke-CimMethod -MethodName WmiSetBrightness -Arguments @{{Timeout=1; Brightness={level}}} | Out-Null")
        if r.returncode != 0:
            return False, "This PC's screen brightness can't be set from here (it only works on a laptop's own screen).", None
    r = _powershell("(Get-CimInstance -Namespace root/WMI -ClassName WmiMonitorBrightness -ErrorAction Stop | Select-Object -First 1).CurrentBrightness")
    now = r.stdout.strip()
    if r.returncode != 0 or not now.isdigit():
        return False, "This PC's screen brightness can't be read from here (it only works on a laptop's own screen).", None
    return True, f"{PC_NAME}'s screen brightness is {now}%.", {"level": int(now)}


def act_screen_off(args):
    """Turns the display off (not sleep, not lock); moving the mouse or a key brings it back."""
    threading.Timer(1.0, lambda: ctypes.windll.user32.PostMessageW(0xFFFF, 0x0112, 0xF170, 2)).start()
    return True, "Turning the PC's screen off.", None


SHUTDOWN_DELAY_S = 30
_power_timer: threading.Timer | None = None
_power_what = ""
_power_lock = threading.Lock()


def _power_go(flag: str):
    global _power_timer
    with _power_lock:
        _power_timer = None
    log.info("%s now, as asked from the phone", "restarting" if flag == "/r" else "shutting down")
    # No /f and no delay in shutdown itself (a delay implies /f): apps with unsaved work still get to ask.
    subprocess.run(["shutdown", flag, "/t", "0"], creationflags=0x08000000)


def _power(flag: str, what: str):
    global _power_timer, _power_what
    with _power_lock:
        if _power_timer:
            _power_timer.cancel()
        _power_timer = threading.Timer(SHUTDOWN_DELAY_S, _power_go, (flag,))
        _power_timer.daemon = True
        _power_what = what
        _power_timer.start()
    try:
        on_notice(f"{what} in {SHUTDOWN_DELAY_S} seconds, asked from your phone. Tray icon → Cancel {what.lower()} to stop it.")
    except Exception:
        log.exception("tray notice failed")
    return True, f"{PC_NAME} will {what.lower()} in {SHUTDOWN_DELAY_S} seconds. Say cancel to stop it.", {"seconds": SHUTDOWN_DELAY_S}


def act_shutdown(args):
    return _power("/s", "Shut down")


def act_restart(args):
    return _power("/r", "Restart")


def power_pending() -> str | None:
    with _power_lock:
        return _power_what if _power_timer else None


def act_cancel_shutdown(args):
    global _power_timer
    with _power_lock:
        t, what = _power_timer, _power_what
        _power_timer = None
    if not t:
        return True, f"Nothing was going to shut down or restart {PC_NAME}.", None
    t.cancel()
    try:
        on_notice(f"{what} cancelled.")
    except Exception:
        log.exception("tray notice failed")
    return True, f"Cancelled: {PC_NAME} won't {what.lower()}.", None


class _KeyInput(ctypes.Structure):
    _fields_ = [("wVk", wintypes.WORD), ("wScan", wintypes.WORD), ("dwFlags", wintypes.DWORD),
                ("time", wintypes.DWORD), ("dwExtraInfo", ctypes.c_size_t)]


class _Input(ctypes.Structure):
    class _U(ctypes.Union):
        # The union is as big as its largest member (MOUSEINPUT); padding keeps SendInput's size check happy.
        _fields_ = [("ki", _KeyInput), ("pad", ctypes.c_byte * 32)]
    _anonymous_ = ("u",)
    _fields_ = [("type", wintypes.DWORD), ("u", _U)]


# Where typing words could run them: a terminal. Refused.
_TERMINAL_CLASSES = {"ConsoleWindowClass", "CASCADIA_HOSTING_WINDOW_CLASS", "mintty", "PuTTY", "VirtualConsoleClass"}
MAX_TYPE = 2000


def _keys(events: list[tuple[int, int, int]]):
    arr = (_Input * len(events))()
    for i, (vk, scan, flags) in enumerate(events):
        arr[i].type = 1  # INPUT_KEYBOARD
        arr[i].ki = _KeyInput(vk, scan, flags, 0, 0)
    ctypes.windll.user32.SendInput(len(events), arr, ctypes.sizeof(_Input))


def act_type(args):
    """Types words into whatever has the keyboard on the PC; Enter at the end only if asked. Never into a terminal."""
    text = str(args.get("text", ""))[:MAX_TYPE]
    enter = str(args.get("enter", "")).lower() == "true"
    if not text and not enter:
        return False, "What should I type?", None
    _u32.GetForegroundWindow.restype = wintypes.HWND
    fg = _u32.GetForegroundWindow()
    if not fg:
        return False, f"{PC_NAME} is locked or nothing is open to type into.", None
    cls = ctypes.create_unicode_buffer(64)
    _u32.GetClassNameW(fg, cls, 64)
    pid = wintypes.DWORD()
    _u32.GetWindowThreadProcessId(fg, ctypes.byref(pid))
    exe = _exe_of(pid.value) or ""
    if cls.value in _TERMINAL_CLASSES or Path(exe).name.lower() in {"windowsterminal.exe", "cmd.exe", "powershell.exe", "pwsh.exe", "conhost.exe"}:
        return False, "A terminal is in front on the PC; I won't type into one.", None
    app = app_name(exe) if exe else "the window in front"
    events = []
    for ch in text.replace("\r\n", "\n").replace("\r", "\n"):
        if ch == "\n":
            events += [(0x0D, 0, 0), (0x0D, 0, 2)]  # Enter
            continue
        for unit in struct.unpack(f"<{len(ch.encode('utf-16-le')) // 2}H", ch.encode("utf-16-le")):
            events += [(0, unit, 4), (0, unit, 4 | 2)]  # KEYEVENTF_UNICODE, down and up
    if enter:
        events += [(0x0D, 0, 0), (0x0D, 0, 2)]
    for i in range(0, len(events), 200):
        _keys(events[i:i + 200])
        time.sleep(0.01)
    said = f"Typed {len(text)} characters into {app}" if text else f"Pressed Enter in {app}"
    return True, said + (" and pressed Enter." if enter and text else "."), {"app": app}


class _MouseInput(ctypes.Structure):
    _fields_ = [("dx", wintypes.LONG), ("dy", wintypes.LONG), ("mouseData", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
                ("time", wintypes.DWORD), ("dwExtraInfo", ctypes.c_size_t)]


class _MInput(ctypes.Structure):
    class _U(ctypes.Union):
        _fields_ = [("mi", _MouseInput), ("pad", ctypes.c_byte * 32)]
    _anonymous_ = ("u",)
    _fields_ = [("type", wintypes.DWORD), ("u", _U)]


def _mouse(events: list[tuple[int, int, int, int]]):
    """(dx, dy, data, flags) mouse events, sent together."""
    arr = (_MInput * len(events))()
    for i, (dx, dy, data, flags) in enumerate(events):
        arr[i].type = 0  # INPUT_MOUSE
        arr[i].mi = _MouseInput(dx, dy, ctypes.c_uint32(data).value, flags, 0, 0)
    ctypes.windll.user32.SendInput(len(events), arr, ctypes.sizeof(_MInput))


_BUTTONS = {"left": (0x0002, 0x0004), "right": (0x0008, 0x0010), "middle": (0x0020, 0x0040)}


def act_pointer(args):
    """The phone's touchpad: move by dx/dy, click / double / right / middle, press and release (drag), scroll."""
    ev: list[tuple[int, int, int, int]] = []
    dx = max(-2000, min(2000, int(args.get("dx", 0) or 0)))
    dy = max(-2000, min(2000, int(args.get("dy", 0) or 0)))
    if dx or dy:
        ev.append((dx, dy, 0, 0x0001))  # MOUSEEVENTF_MOVE
    click = str(args.get("click", "") or "")
    if click:
        down, up = _BUTTONS.get("right" if click == "right" else "middle" if click == "middle" else "left")
        if click == "down":
            ev.append((0, 0, 0, down))
        elif click == "up":
            ev.append((0, 0, 0, up))
        else:
            ev += [(0, 0, 0, down), (0, 0, 0, up)] * (2 if click == "double" else 1)
    scroll = max(-20, min(20, int(args.get("scroll", 0) or 0)))
    if scroll:
        ev.append((0, 0, scroll * 120, 0x0800))  # MOUSEEVENTF_WHEEL, one notch = 120
    hscroll = max(-20, min(20, int(args.get("hscroll", 0) or 0)))
    if hscroll:
        ev.append((0, 0, hscroll * 120, 0x1000))  # MOUSEEVENTF_HWHEEL
    if ev:
        _mouse(ev)
    return True, "", None


# The touchpad's keys: the ones a phone keyboard doesn't type as text.
_NAMED_KEYS = {
    "enter": 0x0D, "backspace": 0x08, "tab": 0x09, "escape": 0x1B, "space": 0x20, "delete": 0x2E,
    "left": 0x25, "up": 0x26, "right": 0x27, "down": 0x28, "home": 0x24, "end": 0x23, "page_up": 0x21, "page_down": 0x22,
    "windows": 0x5B, "f5": 0x74, "f11": 0x7B,
}
_MODS = {"ctrl": 0x11, "alt": 0x12, "shift": 0x10, "win": 0x5B}


def act_key(args):
    """One key from the touchpad's keyboard, with ctrl / alt / shift / win held if asked (ctrl+c, alt+tab…)."""
    name = str(args.get("key", "")).lower()
    vk = _NAMED_KEYS.get(name)
    if vk is None and len(name) == 1 and name.isalnum():
        vk = ord(name.upper())
    if vk is None:
        return False, "Keys: " + ", ".join(_NAMED_KEYS) + ", or a letter or digit with a modifier.", None
    mods = [_MODS[m] for m in str(args.get("mods", "")).lower().split("+") if m in _MODS]
    if name not in _NAMED_KEYS and not set(mods) & {0x11, 0x12, 0x5B}:
        # Letters on their own are typing, which goes through act_type (never into a terminal).
        return False, "Letters and digits go with ctrl, alt or win here; type text instead.", None
    events = [(m, 0, 0) for m in mods] + [(vk, 0, 0), (vk, 0, 2)] + [(m, 0, 2) for m in reversed(mods)]
    _keys(events)
    return True, "", None


# ---------------------------------------------------------------------------------------------- files from the phone

RECEIVED_DIR = (known_folder("Downloads") or Path.home() / "Downloads") / "From phone"
MAX_FILE = 500 * 1024 * 1024        # one file, at most
UPLOAD_IDLE_S = 600                 # an upload with no piece for this long is dropped

_uploads: dict[str, dict] = {}
_uploads_lock = threading.Lock()
on_received = lambda name, path: None  # the tray's "Received photo.jpg" note, set by the UI


def _safe_name(name: str) -> str:
    """Just a file name: no folders, nothing Windows forbids, not empty, not too long."""
    base = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", Path(str(name)).name).strip(" .")
    if not base or base.upper().split(".")[0] in {"CON", "PRN", "AUX", "NUL", "COM1", "LPT1"}:
        base = "file"
    stem, dot, ext = base.rpartition(".")
    if dot and len(ext) <= 10:
        return stem[:120] + "." + ext
    return base[:130]


def _drop_stale_uploads():
    now = time.time()
    with _uploads_lock:
        for uid, u in list(_uploads.items()):
            if now - u["t"] > UPLOAD_IDLE_S:
                try:
                    Path(u["tmp"]).unlink(missing_ok=True)
                except OSError:
                    pass
                del _uploads[uid]


def act_file_begin(args):
    _drop_stale_uploads()
    size = int(args.get("size", -1))
    if size < 0 or size > MAX_FILE:
        return False, f"Files up to {MAX_FILE // (1024 * 1024)} MB can be sent.", None
    RECEIVED_DIR.mkdir(parents=True, exist_ok=True)
    uid = secrets.token_hex(8)
    tmp = RECEIVED_DIR / f".incoming-{uid}.part"
    tmp.write_bytes(b"")
    with _uploads_lock:
        _uploads[uid] = {"name": _safe_name(args.get("name", "file")), "size": size, "got": 0, "next": 0, "tmp": str(tmp), "t": time.time()}
    return True, "Ready.", {"upload": uid}


def act_file_chunk(args):
    uid = str(args.get("upload", ""))
    with _uploads_lock:
        u = _uploads.get(uid)
    if not u:
        return False, "That transfer has expired. Send it again.", None
    if int(args.get("index", -1)) != u["next"]:
        return False, "A piece arrived out of order. Send it again.", None
    data = base64.b64decode(args.get("data", ""))
    if u["got"] + len(data) > u["size"]:
        return False, "The file was bigger than announced.", None
    with open(u["tmp"], "ab") as f:
        f.write(data)
    u["got"] += len(data)
    u["next"] += 1
    u["t"] = time.time()
    return True, "ok", {"got": u["got"]}


def act_file_end(args):
    uid = str(args.get("upload", ""))
    with _uploads_lock:
        u = _uploads.pop(uid, None)
    if not u:
        return False, "That transfer has expired. Send it again.", None
    if u["got"] != u["size"]:
        Path(u["tmp"]).unlink(missing_ok=True)
        return False, "The file didn't arrive whole. Send it again.", None
    target = RECEIVED_DIR / u["name"]
    stem, suffix, n = target.stem, target.suffix, 1
    while target.exists():  # never overwrite: photo.jpg, photo (2).jpg, …
        n += 1
        target = RECEIVED_DIR / f"{stem} ({n}){suffix}"
    Path(u["tmp"]).replace(target)
    log.info("received a file (%d KB)", u["size"] // 1024)
    try:
        on_received(target.name, str(target))
    except Exception:
        log.exception("received-file note failed")
    if args.get("open"):
        os.startfile(target)
        return True, f"Saved {target.name} to Downloads, From phone, and opened it.", {"path": str(target)}
    return True, f"Saved {target.name} to Downloads, From phone.", {"path": str(target)}


def act_open_received(args):
    RECEIVED_DIR.mkdir(parents=True, exist_ok=True)
    os.startfile(RECEIVED_DIR)
    return True, "Opened the From phone folder.", None


# ---------------------------------------------------------------------------------------------- files to the phone

KINDS = {
    "pdf": {".pdf"},
    "image": {".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".heic"},
    "screenshot": {".png", ".jpg", ".jpeg"},
    "video": {".mp4", ".mkv", ".mov", ".avi", ".webm"},
    "document": {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".csv", ".md", ".odt"},
    "audio": {".mp3", ".wav", ".m4a", ".flac", ".ogg"},
    "zip": {".zip", ".rar", ".7z"},
}
OFFER_TTL_S = 900                   # a file offered in a list can be fetched for 15 minutes
_offers: dict[str, tuple[str, float]] = {}      # token → (path, when offered)
_downloads: dict[str, dict] = {}                # token → {path, size, t}
_offers_lock = threading.Lock()


def share_folders() -> dict[str, str]:
    """The folders the phone may take files from, by name (config.json "share_folders")."""
    c = CONFIG.get("share_folders")
    return default_share_folders() if c is None else c


def _allowed(path: Path) -> bool:
    """Inside one of the shared folders, a real file, not hidden."""
    try:
        real = path.resolve()
    except OSError:
        return False
    if not real.is_file() or real.name.startswith(".") or real.suffix.lower() in {".part", ".tmp", ".crdownload", ".lnk", ".ini"}:
        return False
    for root in share_folders().values():
        try:
            real.relative_to(Path(root).resolve())
            return True
        except (ValueError, OSError):
            continue
    return False


def _candidates(folder: str | None, kind: str | None, name: str | None) -> list[Path]:
    """Files in the shared folders (or the one named) matching a kind and part of a name; newest first."""
    roots = share_folders()
    if folder:
        pick, _ = best_match(folder, list(roots))
        roots = {pick: roots[pick]} if pick else {}
    exts = KINDS.get((kind or "").lower())
    want = _norm(name or "")
    found: list[tuple[float, Path]] = []
    seen: set[str] = set()
    for root in roots.values():
        base = Path(root)
        stack = [(base, 0)]
        while stack and len(found) < 20_000:
            d, depth = stack.pop()
            try:
                entries = list(os.scandir(d))
            except OSError:
                continue
            for e in entries:
                try:
                    if e.is_dir(follow_symlinks=False):
                        if depth < 2 and not e.name.startswith(".") and e.name not in SKIP_DIRS:
                            stack.append((Path(e.path), depth + 1))
                        continue
                    if not e.is_file(follow_symlinks=False) or e.name.startswith("."):
                        continue
                    p = Path(e.path)
                    suffix = p.suffix.lower()
                    if suffix in {".part", ".tmp", ".crdownload", ".lnk", ".ini"}:
                        continue
                    if exts and suffix not in exts:
                        continue
                    if kind == "screenshot" and "screenshot" not in (p.name.lower() + str(p.parent).lower()):
                        continue
                    if want and want not in _norm(p.stem):
                        continue
                    key = str(p).lower()
                    if key in seen:
                        continue
                    seen.add(key)
                    found.append((e.stat().st_mtime, p))
                except OSError:
                    continue
    found.sort(key=lambda t: -t[0])
    return [p for _, p in found]


def _offer(p: Path) -> dict:
    token = secrets.token_hex(8)
    with _offers_lock:
        now = time.time()
        for k, (_, t) in list(_offers.items()):
            if now - t > OFFER_TTL_S:
                del _offers[k]
        _offers[token] = (str(p), now)
    st = p.stat()
    # The most specific shared folder it's in: Screenshots rather than Pictures.
    inside = [(len(str(Path(r))), n) for n, r in share_folders().items() if str(p).lower().startswith(str(Path(r)).lower())]
    folder = max(inside)[1] if inside else p.parent.name
    return {"id": token, "name": p.name, "folder": folder, "size": st.st_size, "modified": int(st.st_mtime * 1000)}


def act_find_files(args):
    files = _candidates(args.get("folder"), args.get("kind"), args.get("name"))[:10]
    if not files:
        where = ", ".join(share_folders()) or "no folders"
        return False, f"No matching files in the shared folders ({where}).", []
    offered = [_offer(p) for p in files]
    lines = [f"{i + 1}. {f['name']} ({f['folder']}, {_size(f['size'])}, {time.strftime('%d %b %H:%M', time.localtime(f['modified'] / 1000))})"
             for i, f in enumerate(offered)]
    return True, "\n".join(lines), offered


def _size(n: int) -> str:
    return f"{n / 1_048_576:.1f} MB" if n >= 1_048_576 else f"{max(1, n // 1024)} KB"


def act_file_get_begin(args):
    """Starts sending a file the phone chose from a list (by its id), or the newest match for what it describes."""
    token = str(args.get("id", ""))
    with _offers_lock:
        offered = _offers.get(token)
    if offered:
        path = Path(offered[0])
    else:
        found = _candidates(args.get("folder"), args.get("kind"), args.get("name"))
        if not found:
            return False, "No matching file in the shared folders.", None
        path = found[0]
    if not _allowed(path):
        return False, "That file isn't in a folder the phone may take files from.", None
    size = path.stat().st_size
    if size > MAX_FILE:
        return False, f"That file is {_size(size)}; files up to {MAX_FILE // 1_048_576} MB can be sent.", None
    download = secrets.token_hex(8)
    with _offers_lock:
        now = time.time()
        for k, d in list(_downloads.items()):
            if now - d["t"] > UPLOAD_IDLE_S:
                del _downloads[k]
        _downloads[download] = {"path": str(path), "size": size, "t": now}
    log.info("sending a file to the phone (%s)", _size(size))
    return True, "Ready.", {"download": download, "name": path.name, "size": size}


def act_file_get_chunk(args):
    with _offers_lock:
        d = _downloads.get(str(args.get("download", "")))
    if not d:
        return False, "That transfer has expired. Ask for the file again.", None
    index = int(args.get("index", 0))
    with open(d["path"], "rb") as f:
        f.seek(index * CHUNK)
        data = f.read(CHUNK)
    d["t"] = time.time()
    return True, "ok", {"data": base64.b64encode(data).decode(), "last": (index + 1) * CHUNK >= d["size"]}


CHUNK = 384 * 1024


# ---------------------------------------------------------------------------------------------- folders & the screen

def act_open_folder(args):
    """Opens a folder the PC already knows by name — a shared folder, a workspace, a project, From phone. Never a path."""
    known: dict[str, str] = {}
    known.update(share_folders())
    known.update(workspaces())
    known["From phone"] = str(RECEIVED_DIR)
    for p in all_projects():
        known.setdefault(p.full, p.path)
        known.setdefault(p.name, p.path)
    query = str(args.get("name", "")).strip()
    name, options = best_match(query, list(known))
    if name is None and options and len({known[o] for o in options}) == 1:
        name = options[0]
    if name is None:
        return False, (f"Which one: {', '.join(options)}?" if options else f"I don't know a folder called {query}. I know: " + ", ".join(list(share_folders()) + list(workspaces()))), options
    path = Path(known[name])
    path.mkdir(parents=True, exist_ok=True) if name == "From phone" else None
    if not path.is_dir():
        return False, f"{name} isn't there any more.", None
    os.startfile(path)
    return True, f"Opened {name} on the PC.", {"name": name}


SHOTS_DIR = HOME / "shots"


def act_screenshot(args):
    """A picture of the PC's screen (every monitor), sized for the phone, ready to fetch like a file."""
    from PIL import ImageGrab
    img = ImageGrab.grab(all_screens=True).convert("RGB")
    edge = 1920
    if max(img.size) > edge:
        scale = edge / max(img.size)
        img = img.resize((int(img.width * scale), int(img.height * scale)))
    SHOTS_DIR.mkdir(parents=True, exist_ok=True)
    for old in sorted(SHOTS_DIR.glob("*.jpg"))[:-2]:  # keep only the last few
        old.unlink(missing_ok=True)
    path = SHOTS_DIR / time.strftime("Laptop screen %Y-%m-%d %H.%M.%S.jpg")
    img.save(path, "JPEG", quality=80)
    size = path.stat().st_size
    download = secrets.token_hex(8)
    with _offers_lock:
        _downloads[download] = {"path": str(path), "size": size, "t": time.time()}
    log.info("screenshot for the phone (%s)", _size(size))
    return True, "Took a screenshot.", {"download": download, "name": path.name, "size": size}


# ---------------------------------------------------------------------------------------------- AI agents
# Claude Code, Antigravity, Codex… tell this what they're doing (agent_hook.py, run by their own hooks), and the
# phone listens: "Claude Code needs your approval" while you're away from the laptop. Only the agent, the project
# folder's name and the state are kept, in memory: never prompts, code or messages.

AGENT_NAMES = {"claude": "Claude Code", "antigravity": "Antigravity", "codex": "Codex", "gemini": "Gemini CLI", "cursor": "Cursor"}
AGENT_STATES = {"working", "approval", "question", "done", "ended"}
AGENT_FORGET_S = 6 * 3600     # a session not heard from for this long is dropped
AGENT_WAIT_S = 30             # the phone's question waits this long for a change before answering "nothing new"


class _LastInput(ctypes.Structure):
    _fields_ = [("cbSize", ctypes.c_uint), ("dwTime", ctypes.c_uint)]


def idle_seconds() -> int:
    """Seconds since the keyboard or mouse was last touched: the phone speaks up only when nobody is at the laptop."""
    li = _LastInput(ctypes.sizeof(_LastInput), 0)
    if not ctypes.windll.user32.GetLastInputInfo(ctypes.byref(li)):
        return 0
    return max(0, ((ctypes.windll.kernel32.GetTickCount() & 0xFFFFFFFF) - li.dwTime) & 0xFFFFFFFF) // 1000


class Agents:
    def __init__(self):
        self.cond = threading.Condition()
        self.version = 0
        self.sessions: dict[str, dict] = {}

    def report(self, agent: str, session: str, project: str, state: str) -> None:
        if state not in AGENT_STATES:
            return
        key = f"{agent}:{session}"
        now = time.time()
        with self.cond:
            old = self.sessions.get(key)
            if state == "ended":
                if not old:
                    return
                del self.sessions[key]
            elif old and old["state"] == state:
                old["seen"] = now
                return
            else:
                # How long it worked before this: a long task finishing is news even to someone at the laptop.
                took = int(now - old["since"]) if old and old["state"] == "working" else (old or {}).get("took", 0)
                self.sessions[key] = {"agent": agent, "project": project, "state": state, "since": now, "seen": now,
                                      "change": self.version + 1, "took": took}
            self.version += 1
            self.cond.notify_all()
        log.info("%s: %s", AGENT_NAMES.get(agent, agent), state)

    def snapshot(self) -> dict:
        now = time.time()
        with self.cond:
            for k in [k for k, v in self.sessions.items() if now - v["seen"] > AGENT_FORGET_S]:
                del self.sessions[k]
            sessions = [{"key": k, "agent": AGENT_NAMES.get(v["agent"], v["agent"].title()), "project": v["project"],
                         "state": v["state"], "ago": int(now - v["since"]), "change": v["change"], "took": v.get("took", 0)}
                        for k, v in sorted(self.sessions.items(), key=lambda kv: -kv[1]["since"])]
            return {"v": self.version, "idle": idle_seconds(), "sessions": sessions}

    def wait(self, since: int, timeout: float) -> dict:
        with self.cond:
            self.cond.wait_for(lambda: self.version != since, timeout)
        return self.snapshot()


AGENTS = Agents()


def handle_agent(req: dict) -> dict:
    """An agent_hook.py on this PC: never from the network (the handler checks)."""
    agent = re.sub(r"[^a-z0-9_-]", "", str(req.get("agent", "")).lower())[:20] or "agent"
    project = re.sub(r"[\x00-\x1f]", "", str(req.get("project", "")))[:60]
    AGENTS.report(agent, str(req.get("session", ""))[:64], project, str(req.get("state", "")))
    return {"ok": True}


def _agent_words(a: dict) -> str:
    mins = a["ago"] // 60
    ago = "just now" if mins < 1 else f"{mins} min ago" if mins < 90 else f"{mins // 60} h ago"
    since = "" if mins < 1 else f" for {mins} min" if mins < 90 else f" for {mins // 60} h"
    where = f" in {a['project']}" if a["project"] else ""
    return {
        "working": f"{a['agent']}{where} is working (started {ago})",
        "approval": f"{a['agent']}{where} is waiting for your approval{since}",
        "question": f"{a['agent']}{where} is asking you something{since}",
        "done": f"{a['agent']}{where} finished {ago}",
    }.get(a["state"], f"{a['agent']}{where}: {a['state']}")


def act_agents(args):
    snap = AGENTS.snapshot()
    if not snap["sessions"]:
        if not agent_hooks_on():
            return True, (f"Not watching AI agents on {PC_NAME}: turn on Watch AI agents in the JARVIS Link tray menu. "
                          "It covers Claude Code, Antigravity and Codex."), snap
        return True, f"No AI agent on {PC_NAME} has reported anything in the last few hours.", snap
    return True, ". ".join(_agent_words(a) for a in snap["sessions"][:6]) + ".", snap


def act_agents_wait(args):
    """The phone's long wait: answers as soon as something changes, or after AGENT_WAIT_S with nothing new."""
    try:
        since = int(args.get("since", -1))
    except (TypeError, ValueError):
        since = -1
    return True, "", AGENTS.wait(since, AGENT_WAIT_S)


# ------------------------------------------------ setting up the agents' hooks (tray → Watch AI agents)
# Ours are told apart by agent_hook.py in the command, so the user's own hooks (and other tools') are left alone.

HOOK_SCRIPT = Path(__file__).resolve().with_name("agent_hook.py")
CLAUDE_SETTINGS = Path.home() / ".claude" / "settings.json"
ANTIGRAVITY_HOOKS = Path.home() / ".gemini" / "config" / "hooks.json"
CODEX_CONFIG = Path.home() / ".codex" / "config.toml"
CLAUDE_EVENTS = ["UserPromptSubmit", "PostToolUse", "Notification", "Stop", "SessionEnd"]
ANTIGRAVITY_EVENTS = ["PreInvocation", "Stop"]


def _hook_python() -> str:
    python = Path(sys.executable).with_name("python.exe")  # the tray runs under pythonw; hooks want the console one
    return str(python if python.exists() else sys.executable)


def hook_command(agent: str) -> str:
    return f'"{_hook_python()}" -S "{HOOK_SCRIPT}" {agent}'


def _short_path(path: str) -> str:
    """Windows' 8.3 name for [path] (no spaces), or the path as it is if there isn't one."""
    buf = ctypes.create_unicode_buffer(1024)
    return buf.value if ctypes.windll.kernel32.GetShortPathNameW(str(path), buf, 1024) else str(path)


def antigravity_command(event: str) -> str:
    """
    Antigravity's hook command: short paths, because it hands the command to cmd.exe with its quotes escaped (a path
    with a space, like "AI ASSISTANTS", then isn't found); and the event named, because its payload doesn't say which.
    """
    return f"{_short_path(_hook_python())} -S {_short_path(str(HOOK_SCRIPT))} antigravity {event}"


def _ours(entry) -> bool:
    return isinstance(entry, dict) and any("agent_hook.py" in str(h.get("command", "")) for h in entry.get("hooks", []) if isinstance(h, dict))


def _write_json(path: Path, data) -> None:
    backup = path.with_name(path.name + ".before-jarvis")
    if path.exists() and not backup.exists():
        shutil.copy2(path, backup)  # the file as it was before JARVIS Link first touched it
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n", "utf-8")
    os.replace(tmp, path)


def _claude_hooks(on: bool) -> str | None:
    if not CLAUDE_SETTINGS.parent.exists():
        return None
    data = json.loads(CLAUDE_SETTINGS.read_text("utf-8")) if CLAUDE_SETTINGS.exists() else {}
    hooks = data.setdefault("hooks", {})
    for event in CLAUDE_EVENTS:
        kept = [e for e in hooks.get(event, []) if not _ours(e)]
        if on:
            kept.append({"hooks": [{"type": "command", "command": hook_command("claude"), "timeout": 5}]})
        if kept:
            hooks[event] = kept
        else:
            hooks.pop(event, None)
    if not hooks:
        data.pop("hooks")
    _write_json(CLAUDE_SETTINGS, data)
    return "Claude Code"


def _antigravity_hooks(on: bool) -> str | None:
    if not ANTIGRAVITY_HOOKS.parent.parent.exists():
        return None
    data = json.loads(ANTIGRAVITY_HOOKS.read_text("utf-8")) if ANTIGRAVITY_HOOKS.exists() else {}
    data.pop("jarvis-link", None)
    if on:
        # Its events without a matcher take the command itself, not Claude Code's {"hooks": [...]} (that's refused:
        # "command hook must specify 'command'").
        data["jarvis-link"] = {e: [{"type": "command", "command": antigravity_command(e), "timeout": 5}]
                               for e in ANTIGRAVITY_EVENTS}
    ANTIGRAVITY_HOOKS.parent.mkdir(parents=True, exist_ok=True)
    _write_json(ANTIGRAVITY_HOOKS, data)
    return "Antigravity"


def _codex_hooks(on: bool) -> str | None:
    """Codex runs one program when a turn finishes (notify = [...], a top-level key: so it goes first in the file)."""
    if not CODEX_CONFIG.parent.exists():
        return None
    text = CODEX_CONFIG.read_text("utf-8") if CODEX_CONFIG.exists() else ""
    lines = [ln for ln in text.splitlines() if not (ln.startswith("notify") and "agent_hook.py" in ln)]
    if on:
        if any(re.match(r"\s*notify\s*=", ln) for ln in lines):
            return None  # the user's own notify program: left as it is
        lines.insert(0, "notify = " + json.dumps([_hook_python(), "-S", str(HOOK_SCRIPT), "codex"]))
    new = "\n".join(lines) + ("\n" if lines else "")
    if new != text:
        backup = CODEX_CONFIG.with_name(CODEX_CONFIG.name + ".before-jarvis")
        if CODEX_CONFIG.exists() and not backup.exists():
            shutil.copy2(CODEX_CONFIG, backup)
        CODEX_CONFIG.write_text(new, "utf-8")
    return "Codex"


def agent_hooks_on() -> bool:
    try:
        if "agent_hook.py" in CLAUDE_SETTINGS.read_text("utf-8"):
            return True
    except OSError:
        pass
    try:
        return '"jarvis-link"' in ANTIGRAVITY_HOOKS.read_text("utf-8")
    except OSError:
        return False


def set_agent_hooks(on: bool) -> str:
    """Adds (or removes) our hook in each agent found on this PC. Words for the tray notice."""
    done, failed = [], []
    for name, fn in (("Claude Code", _claude_hooks), ("Antigravity", _antigravity_hooks), ("Codex", _codex_hooks)):
        try:
            if fn(on):
                done.append(name)
        except Exception:
            log.exception("setting up %s's hook failed", name)
            failed.append(name)
    log.info("agent hooks %s: %s", "on" if on else "off", ", ".join(done) or "none")
    words = " and ".join([", ".join(done[:-1]), done[-1]] if len(done) > 1 else done)
    if on:
        text = (f"Watching {words}. Your phone hears when they finish or need you, if you're away from the laptop. "
                "Sessions already open start reporting after a restart.") if done else "No AI agents found on this PC."
    else:
        text = f"Stopped watching {words}." if done else "Nothing to stop."
    if failed:
        text += f" Couldn't change {', '.join(failed)}'s settings (see the log)."
    return text


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
    "file_begin": act_file_begin,
    "file_chunk": act_file_chunk,
    "file_end": act_file_end,
    "open_received": act_open_received,
    "find_files": act_find_files,
    "file_get_begin": act_file_get_begin,
    "file_get_chunk": act_file_get_chunk,
    "open_folder": act_open_folder,
    "screenshot": act_screenshot,
    "usage": act_usage,
    "disk": act_disk,
    "open_apps": act_open_apps,
    "downloads": act_downloads,
    "volume": act_volume,
    "brightness": act_brightness,
    "screen_off": act_screen_off,
    "shutdown": act_shutdown,
    "restart": act_restart,
    "cancel_shutdown": act_cancel_shutdown,
    "type": act_type,
    "close_app": act_close_app,
    "switch_to": act_switch_to,
    "show_desktop": act_show_desktop,
    "clipboard_get": act_clipboard_get,
    "pointer": act_pointer,
    "key": act_key,
    "agents": act_agents,
    "agents_wait": act_agents_wait,
}


# ---------------------------------------------------------------------------------------------- network

# Adapters a phone on the Wi-Fi can never reach: WSL / Hyper-V, virtual machines, VPNs, Bluetooth.
VIRTUAL_ADAPTER = re.compile(r"vethernet|wsl|hyper-v|virtualbox|vmware|vpn|wintun|tap-|wireguard|tailscale|zerotier|bluetooth|loopback|docker", re.I)
PRIVATE_IP = re.compile(r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)")


def local_ips() -> list[str]:
    """
    This PC's addresses on the home network: private ranges, real adapters only (Wi-Fi, Ethernet), the one a LAN
    packet would leave by first. Announcing WSL's or a VPN's address sent phones to one they can't reach.
    """
    first = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("192.0.2.1", 9))  # nothing is sent: this only picks the interface a LAN packet would use
        first = s.getsockname()[0]
        s.close()
    except OSError:
        pass
    ips: list[str] = []
    try:
        import ifaddr
        for adapter in ifaddr.get_adapters():
            if VIRTUAL_ADAPTER.search(adapter.nice_name or ""):
                continue
            ips += [ip.ip for ip in adapter.ips if isinstance(ip.ip, str)]
    except Exception:  # without ifaddr: every address the PC's name has, as before
        try:
            ips += [info[4][0] for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET)]
        except OSError:
            pass
    ips = [ip for ip in ips if PRIVATE_IP.match(ip)]
    if first in ips:  # the default route's first, when it is one of the real ones (not the VPN's)
        ips.remove(first)
        ips.insert(0, first)
    return list(dict.fromkeys(ips))


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
            first = True
            while True:
                try:
                    req = read_frame(self.request)
                except (socket.timeout, ConnectionError):
                    return
                if not req:
                    return
                t = req.get("t")
                if t == "hello":
                    reply = {"ok": True, "id": AGENT_ID, "name": PC_NAME, "v": VERSION}
                elif t == "pair":
                    reply = handle_pair(req)
                elif t == "cmd":
                    reply = handle_cmd(req)
                elif t == "agent" and peer == "127.0.0.1":
                    reply = handle_agent(req)
                else:
                    reply = {"ok": False, "error": "unknown"}
                write_frame(self.request, reply)
                if first:
                    # Kept open for the next request (the touchpad), and closed after a minute of nothing.
                    first = False
                    self.request.settimeout(60)
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
    zc = None
    info = None
    last: list[str] = []
    while True:
        ips = local_ips()
        if ips != last:
            # Started fresh on the new addresses: a Zeroconf made before the Wi-Fi came up (just after a restart)
            # keeps listening on what was there then, and phones never heard it — they had to pair again.
            try:
                if zc:
                    if info:
                        zc.unregister_service(info)
                    zc.close()
                zc = info = None
                if ips:
                    zc = Zeroconf(interfaces=ips, ip_version=IPVersion.V4Only)
                    info = ServiceInfo(SERVICE, f"JARVIS Link {AGENT_ID[:8]}.{SERVICE}", port=PORT, parsed_addresses=ips,
                                       properties={"id": AGENT_ID, "name": PC_NAME})
                    zc.register_service(info)
                log.info("advertising on %s", ", ".join(ips) or "nothing (no network)")
                last = ips
            except Exception:
                log.exception("mDNS registration failed")
        time.sleep(15)


# ---------------------------------------------------------------------------------------------- tray & windows

def open_text_file(path: Path) -> None:
    """Opens a settings or log file for editing: in whatever opens that kind of file, else Notepad. Many PCs have
    nothing set for .json, and the tray's Settings did nothing at all there."""
    try:
        os.startfile(path)
    except OSError:
        subprocess.Popen(["notepad.exe", str(path)])


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
        """JARVIS's robot with LINK on its screen (icon.png, next to this file); a plain ring if it's missing."""
        try:
            return Image.open(Path(__file__).with_name("icon.png")).convert("RGBA")
        except OSError:
            img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
            d = ImageDraw.Draw(img)
            d.ellipse((4, 4, 60, 60), outline=(255, 178, 36, 255), width=6)
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

    def received(name, path):
        def note():
            try:
                icon.notify(f"Received {name} from your phone (Downloads\\From phone).", APP)
            except Exception:
                log.exception("tray notice failed")
        jobs.put(note)

    global on_received
    on_received = received

    def notice(text):
        def note():
            try:
                icon.notify(text, APP)
            except Exception:
                log.exception("tray notice failed")
        jobs.put(note)

    global on_notice
    on_notice = lambda text: (notice(text), jobs.put(icon.update_menu))

    def toggle_startup(icon_, item):
        start_with_windows(not STARTUP_FILE.exists())

    def toggle_agents(icon_, item):
        notice(set_agent_hooks(not agent_hooks_on()))
        jobs.put(icon.update_menu)

    def quit_(icon_, item):
        icon.stop()
        jobs.put(root.destroy)

    icon = pystray.Icon(
        "jarvis_link", icon_image(), APP,
        menu=pystray.Menu(
            pystray.MenuItem("Open JARVIS Link", lambda i, it: jobs.put(show_window), default=True),
            pystray.MenuItem("Pair a phone…", lambda i, it: jobs.put(lambda: show_window(pair_now=True))),
            pystray.MenuItem("Files from phone", lambda i, it: act_open_received({})),
            pystray.MenuItem("Settings (folders)…", lambda i, it: open_text_file(CONFIG_FILE)),
            pystray.MenuItem(lambda item: f"Cancel {(power_pending() or 'shutdown').lower()}",
                             lambda i, it: act_cancel_shutdown({}), visible=lambda item: power_pending() is not None),
            pystray.MenuItem("Start with Windows", toggle_startup, checked=lambda item: STARTUP_FILE.exists()),
            pystray.MenuItem("Watch AI agents", toggle_agents, checked=lambda item: agent_hooks_on()),
            pystray.MenuItem("Open log", lambda i, it: open_text_file(LOG_FILE)),
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
