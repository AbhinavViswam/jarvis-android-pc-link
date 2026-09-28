# JARVIS Link

Lets JARVIS on your phone do a few things on this PC over your home Wi-Fi — independent of Mark-LIV.

"Open my jarvis-android project on the laptop", "open Spotify on the PC", "send this link to my laptop",
"copy this to my laptop", "pause the music on the PC", "lock my laptop", "is my laptop on?"

## Setup
1. `pip install -r requirements.txt`
2. `pythonw jarvis_link.py` — an icon appears in the tray; click it to open the JARVIS Link window (paired phones with Forget, and Show QR code / New code to pair). Tray → **Start with Windows** to keep it running.
3. In the window, **Show QR code** (or tray → Pair a phone…). On the phone: JARVIS → Settings → Abilities → **PC link** →
   Scan the laptop's code. Pairing is remembered on both sides; do it once.
4. Allow Python through Windows Firewall on **Private** networks if Windows asks.

## Settings
Tray → **Project folders…** opens `%APPDATA%\JARVIS Link\config.json`:
- `workspaces`: named folders searched for projects (a folder with .git, package.json, build.gradle, pyproject…), e.g. `{"Abhi": "C:\DILSHA\ABHI", "RateUp": "C:\DILSHA\rateup-abhi"}` — "open the RateUp api" picks rateup-api there.
- `aliases`: your own names, e.g. `"jarvis": "C:\...\jarvis-android"`.
- `editor`: `code` (VS Code) by default; `explorer` just opens the folder.

## Safety
- Only phones paired by QR are answered; Forget one in the window (Forget on the phone removes it here too).
- Every request/reply is AES-256-GCM encrypted with that phone's key, time-stamped, replay-checked.
- Only the fixed actions in `ACTIONS` exist; nothing sent is ever run as a command.
- Home-network addresses only. Log: tray → Open log.

`python test_link.py` pairs a pretend phone and runs the actions (uses a temporary folder, not your pairing).
