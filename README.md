# JARVIS Link

Lets JARVIS on your phone do a few things on this PC over your home Wi-Fi — independent of Mark-LIV.

"Open my jarvis-android project on the laptop", "open Spotify on the PC", "send this link to my laptop",
"copy this to my laptop", "send my latest photo to the laptop", "pause the music on the PC", "lock my laptop", "is my laptop on?"
Share → **Send to laptop** from any app sends photos and files to `Downloads\From phone`.
"Get me the latest screenshot from my laptop", "send me that PDF from Downloads" bring files the other way, into the phone's Downloads/JARVIS — only from the folders in `share_folders`.
"Open Downloads on the laptop", "open the RateUp folder" (folders it knows by name), and "what's on my laptop screen?" (a screenshot JARVIS looks at).

## Setup
1. Double-click **setup.bat**: it makes `.venv` here and installs the exact versions in `requirements.txt` (needs Python 3
   from python.org). Run it again after changing a version, or if Python itself is reinstalled or upgraded.
2. Double-click **start.bat** — an icon appears in the tray; click it to open the JARVIS Link window (paired phones with Forget, and Show QR code / New code to pair). Tray → **Start with Windows** to keep it running.
3. In the window, **Show QR code** (or tray → Pair a phone…). On the phone: JARVIS → Settings → Abilities → **PC link** →
   Scan the laptop's code. Pairing is remembered on both sides; do it once.
4. Allow Python through Windows Firewall on **Private** networks if Windows asks.

## Settings
Tray → **Settings (folders)…** opens `%APPDATA%\JARVIS Link\config.json`:
- `workspaces`: named folders searched for projects (a folder with .git, package.json, build.gradle, pyproject…), e.g. `{"Abhi": "C:\DILSHA\ABHI", "RateUp": "C:\DILSHA\rateup-abhi"}` — "open the RateUp api" picks rateup-api there.
- `aliases`: your own names, e.g. `"jarvis": "C:\...\jarvis-android"`.
- `share_folders`: the only folders the phone may take files from (Downloads, Desktop, Documents, Pictures, Screenshots by default — the real ones, OneDrive included).
- `editor`: `code` (VS Code) by default; `explorer` just opens the folder.

## Safety
- Only phones paired by QR are answered; Forget one in the window (Forget on the phone removes it here too).
- Every request/reply is AES-256-GCM encrypted with that phone's key, time-stamped, replay-checked.
- Only the fixed actions in `ACTIONS` exist; nothing sent is ever run as a command.
- Home-network addresses only. Log: tray → Open log.

`.venv\Scripts\python test_link.py` pairs a pretend phone and runs the actions (uses a temporary folder, not your pairing).
