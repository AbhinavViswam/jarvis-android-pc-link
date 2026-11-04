# JARVIS Link

Lets JARVIS on your phone do a few things on this PC over your home Wi-Fi, or from **any network** with Tailscale (see
[Use it from anywhere](#use-it-from-anywhere-tailscale)) — independent of Mark-LIV.

"Open my jarvis-android project on the laptop", "open Spotify on the PC", "send this link to my laptop",
"copy this to my laptop", "send my latest photo to the laptop", "pause the music on the PC", "lock my laptop", "is my laptop on?"
Share → **Send to laptop** from any app sends photos and files to `Downloads\From phone`.
"Get me the latest screenshot from my laptop", "send me that PDF from Downloads" bring files the other way, into the phone's Downloads/JARVIS — only from the folders in `share_folders`.
"Open Downloads on the laptop", "open the RateUp folder" (folders it knows by name), and "what's on my laptop screen?" (a screenshot JARVIS looks at).
"Is my laptop busy?" (CPU, memory, the busiest apps), "how much space is left on the laptop?", "what's open on my laptop?"
(app names only, never window titles), "has my download finished?" (unfinished browser downloads in Downloads, and whether they're moving).
"Set the laptop volume to 30", "mute the laptop", "brightness to 50" (a laptop's own screen), "turn the laptop screen off",
"shut down / restart my laptop" (the phone asks first; it happens after 30 seconds, and "cancel" or tray → Cancel stops it;
apps with unsaved work still get to ask), "type this on my laptop" (into the window in front; never into a terminal; the phone
asks first if it would press Enter).

## Setup
1. Double-click **setup.bat**: it makes `.venv` here and installs the exact versions in `requirements.txt` (needs Python 3
   from python.org). Run it again after changing a version, or if Python itself is reinstalled or upgraded.
2. Double-click **start.bat** — an icon appears in the tray; click it to open the JARVIS Link window (paired phones with Forget, and Show QR code / New code to pair). Tray → **Start with Windows** to keep it running.
3. In the window, **Show QR code** (or tray → Pair a phone…). On the phone: JARVIS → Settings → Abilities → **PC link** →
   Scan the laptop's code. Pairing is remembered on both sides; do it once.
4. Allow Python through Windows Firewall on **Private** networks if Windows asks.

## Use it from anywhere (Tailscale)
Out of the box the phone and PC must be on the same Wi-Fi. To use the PC from mobile data, the office or a café, turn
on **Work on any network**. It uses [Tailscale](https://tailscale.com), a free private network between your own
devices: no router settings, and nothing on this PC is opened to the internet.

1. Install Tailscale on the PC: **[Download for Windows](https://tailscale.com/download/windows)**, then sign in.
2. Install Tailscale on the phone: **[Get it on Google Play](https://play.google.com/store/apps/details?id=com.tailscale.ipn)**,
   then sign in with the **same account** and keep it connected.
3. In the JARVIS Link window, tick **Work on any network (Tailscale)** (or tray → Work on any network).
4. Use the link once while both are on the home Wi-Fi (or pair again). The phone learns the PC's Tailscale address
   and uses it whenever the home Wi-Fi can't reach the PC.

How it stays safe: only devices signed in to your Tailscale account can reach the PC at all, and on top of that every
request is still sealed with the phone's own key, exactly as at home. Turn the switch off and the PC answers only the
home Wi-Fi again.

If JARVIS keeps reconnecting on the phone once Tailscale is on, the phone can't look up addresses: Tailscale's DNS
clashes with a Private DNS such as AdGuard. In Tailscale on the phone: Settings → turn off **Use Tailscale DNS**, then
reconnect. JARVIS Link uses the PC's Tailscale address directly, so nothing is lost. Android allows one VPN at a time, so Tailscale on the phone can't run alongside another VPN app.

## AI agents
Tray → **Watch AI agents** adds a hook to Claude Code, Antigravity and Codex (whichever are installed; your own hooks
are left alone, and the first change keeps a `.before-jarvis` copy of each file). They then run `agent_hook.py` on
their events, and the phone (Settings → PC link → AI agents on the laptop) gets a notification when one finishes or
waits for approval **while nobody has touched the laptop for a minute**. "Is Claude done?" asks too. Only the agent,
the project folder's name and the state leave the laptop, never prompts, code or messages. No AI model is involved,
so it uses no tokens. Antigravity has no "waiting for approval" event, so it only reports working and finished.
Codex reports only finished. Another agent can report too: `python -S agent_hook.py <name>` with its event JSON on stdin.

## Settings
Tray → **Settings (folders)…** opens `%APPDATA%\JARVIS Link\config.json`:
- `workspaces`: named folders searched for projects (a folder with .git, package.json, build.gradle, pyproject…), e.g. `{"Abhi": "C:\\DILSHA\\ABHI", "RateUp": "C:/DILSHA/rateup-abhi"}` — "open the RateUp api" picks rateup-api there.
- `aliases`: your own names, e.g. `"jarvis": "C:\\...\\jarvis-android"`.

In a path write `\\` or `/`, never a single `\` (that isn't valid JSON). Changes take effect when you save the file. If
the file has a mistake, JARVIS Link keeps the settings it has (the defaults, if it was just started), copies the broken file to `config.json.bad` and
tells you in the tray; it never overwrites your file. This PC's id (what phones and Orion know it by) is kept apart,
in `%APPDATA%\JARVIS Link\id`, so a mistake here can never unpair anything.
- `share_folders`: the only folders the phone may take files from (Downloads, Desktop, Documents, Pictures, Screenshots by default — the real ones, OneDrive included).
- `editor`: `code` (VS Code) by default; `explorer` just opens the folder.
- `any_network`: `false` by default; `true` also answers phones on your Tailscale (the window's switch sets it).

## Safety
- Only phones paired by QR are answered; Forget one in the window (Forget on the phone removes it here too).
- Every request/reply is AES-256-GCM encrypted with that phone's key, time-stamped, replay-checked.
- Only the fixed actions in `ACTIONS` exist; nothing sent is ever run as a command.
- Home-network addresses only, plus your own Tailscale (100.64.0.0/10) when **Work on any network** is on.
- An address that sends 10 requests with the wrong key (or garbage) within 10 minutes is ignored for 10 minutes.
- Files from the phone are marked as from another computer (like a download). "Send and open" opens documents,
  pictures, music and videos only; anything else is shown in its folder, never run.
- Log: tray → Open log.

`.venv\Scripts\python test_link.py` pairs a pretend phone and runs the actions (uses a temporary folder, not your pairing).
