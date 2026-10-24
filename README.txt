LINUX TERMINAL COMMANDER
========================
GitHub: https://github.com/0Badwa/linux-terminal-commander
License: MIT | Platform: Linux | Status: development, not a stable release

WHAT IS IT?
-----------
A self-hosted Python MCP server that connects a Linux computer to ChatGPT
through YOUR OWN OpenAI Secure MCP Tunnel. It is not a cloud terminal
hosting service, an official OpenAI product, or a remote desktop application.

The current implementation exposes 39 MCP tools for:
- System information and approved directories.
- Reading, listing, searching, writing and editing local text files.
- Git status, history, diffs and restricted branch/worktree operations.
- Bash commands (isolated by default; full Linux user shell only if locally approved).
- Running, tracking, interacting with and stopping supervised terminal sessions.
- Selected test/build/Git jobs, status and output.

REQUIREMENTS
------------
Linux (originally tested on Ubuntu 24.04), Python 3.12 recommended,
Git, python3-venv/pip, bubblewrap, util-linux and optionally Zenity.
You also need the separately installed official OpenAI tunnel-client,
your own OpenAI Secure MCP Tunnel ID, a restricted runtime key with
Tunnels Read + Use, and access to custom MCP plugins in ChatGPT.

Ubuntu/Debian prerequisites:
  sudo apt update
  sudo apt install git python3 python3-venv python3-pip bubblewrap util-linux zenity

INSTALL AND CONNECT
-------------------
1. Clone:
   git clone https://github.com/0Badwa/linux-terminal-commander.git
   cd linux-terminal-commander

2. Install local Python dependencies:
   ./install.sh

3. Install the official tunnel-client:
   https://github.com/openai/tunnel-client

   Verify:
   tunnel-client --version
   tunnel-client help quickstart

4. Create your OWN Secure MCP Tunnel and restricted runtime key following:
   https://developers.openai.com/api/docs/guides/secure-mcp-tunnels

   Tunnel creation requires Tunnels Read + Manage; running the client
   requires Tunnels Read + Use. ChatGPT plugin access is separate.
   Associate the tunnel with the intended ChatGPT workspace.

5. Configure (replace placeholder with YOUR real tunnel ID):
   .venv/bin/python configure.py --tunnel-id "<YOUR_TUNNEL_ID>"

   To use a different Git project, add:
   --project "/absolute/path/to/existing/git-checkout"

6. Start in the foreground:
   .venv/bin/python run_client.py --terminal-input

   Enter YOUR restricted key locally (input is hidden).
   Keep this process running; press Ctrl+C to stop.

7. In ChatGPT: Plugins > + > Add custom MCP server >
   Connection: Tunnel. Select/enter YOUR tunnel ID, configure
   authentication, review and confirm the security warning.
   Test by asking for the Linux distribution.

OPTIONAL USER SERVICE
---------------------
Only after the foreground tunnel works. Do not run both at once.

  .venv/bin/python setup_runtime_secret.py --terminal-input
  .venv/bin/python install_service.py
  systemctl --user daemon-reload
  systemctl --user enable --now linux-terminal-commander.service

Check: systemctl --user status linux-terminal-commander.service
Logs:  journalctl --user -u linux-terminal-commander.service -n 80 --no-pager
Stop:  systemctl --user disable --now linux-terminal-commander.service

SECURITY
--------
Default isolated mode uses Bubblewrap and limited source snapshots.
Host mode is opt-in via MCP set_config_value, approval_mode =
desktop_compatible, with a LOCAL Zenity dialog. After activation,
remote callers can run Bash as your Linux user without asking on
every command. Protect ChatGPT access and keys. Do NOT run as root.

Never publish or commit profiles/, runtime/, workspace/, .venv/,
approved_roots.json, local keys, private files or logs.
Each user must have their own tunnel and credentials.

TESTS AND LIMITATIONS
---------------------
  .venv/bin/python -m compileall -q .
  .venv/bin/python -m unittest -q test_server test_phase2 test_phase3 test_phase4 test_phase5 test_phase51 test_portability

132/132 tests passed in the original Ubuntu development environment.
The Python dependencies and test tunnel profile were checked.
A fresh live installation on a second Linux account/distribution
has NOT yet been independently validated. Do not call this a stable
v1.0 release.

FOR FULL INSTALLATION, SECURITY DETAILS, TROUBLESHOOTING,
ARCHITECTURE AND LINKS, READ README.md.

The official tunnel-client is distributed separately under its own
license. Linux Terminal Commander is an independent MIT project.
