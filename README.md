# Linux Terminal Commander

**Self-hosted Linux terminal and filesystem tools for ChatGPT, connected through a private MCP tunnel.**

Linux Terminal Commander turns a Linux computer into a user-controlled [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server. After connecting your **own** OpenAI Secure MCP Tunnel to ChatGPT, you can inspect files, work with Git, run terminal commands, and supervise processes from a conversation.

**Project:** [0Badwa/linux-terminal-commander](https://github.com/0Badwa/linux-terminal-commander)
**Platform:** Linux; developed and tested primarily on Ubuntu 24.04
**Technology:** Python 3.12, MCP, Bubblewrap, OpenAI's separately installed `tunnel-client`, optional systemd user service
**License:** MIT (this repository)
**Status:** Development / public source release — **not yet validated as a complete fresh install on a second Linux account or distribution**.

> **Security warning:** Enabling **host terminal mode** gives trusted remote MCP callers the ability to run commands as your Linux user. After one local approval, commands do not require a new confirmation for every operation. The default is the more restricted **isolated** mode. Read [Security and permissions](#security-and-permissions) before connecting.

## What can it do?

The current MCP server exposes **39 tools** across these areas:

| Area | Capabilities |
| --- | --- |
| Computer information | Linux distribution, hostname, current user, active configuration and allowed roots. |
| Files and directories | List, read, search and inspect text files; create and edit files; manage directories and move files with safety/version checks. |
| Git projects | Inspect status, commits, branches and diffs; some managed-branch/worktree and commit operations with explicit constraints. |
| Linux terminal | Run Bash commands with bounded time/output, in isolated mode or — if explicitly authorized locally — as the Linux user on the host. |
| Long-running processes | Start detached commands (including PTY sessions), read paginated output, send input, inspect status and terminate **tracked** sessions. |
| Task and job helpers | Bounded background test/build/Git jobs, status and output; some Gradle presets are tailored to a configured primary project. |
| Approvals and configuration | Local approval dialogs, restricted/default working directories, timeouts, concurrency limits and audit metadata. |

Example requests after you connect it: “Show the Git status of my project”, “Find this function in the source tree”, “List the biggest files in this directory”, “Run the test suite and show its result”, “Read a log and summarize the error”, or “Start this command and show its output.” The remote assistant is not automatically authorized to perform destructive actions merely because the tool is present.

**Not included:** a shared cloud server, hosted tunnel relay, ready-made ChatGPT account, tunnel access credentials, GUI remote desktop, Android support or a Windows version. Each user runs their **own** local server and **own** tunnel. ChatGPT/Platform access depends on the account and workspace permissions.

## How it works

```text
Your ChatGPT workspace / private MCP plugin
           |
           | OpenAI Secure MCP Tunnel (outbound HTTPS)
           v
Your Linux computer: official tunnel-client
           |
           | local MCP over stdio
           v
Linux Terminal Commander (Python MCP server)
           |
           +-- isolated Bubblewrap execution (default)
           +-- local, guarded file and Git tools
           +-- host Bash (only after explicit local activation)
```

The computer needs **outbound HTTPS** access to OpenAI; the default setup does **not** require a publicly reachable IP address or inbound port forwarding. The tunnel connection is managed by the official OpenAI client, not by infrastructure operated by this project.

See [OpenAI: Secure MCP Tunnel](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels) and the [official tunnel-client repository](https://github.com/openai/tunnel-client).

## Requirements

- **Linux desktop or server**, tested mainly on **Ubuntu 24.04**. Other distributions are not independently validated yet.
- **Python 3.12 recommended**, with Python virtual-environment support and pip, plus **Git**.
- **Bubblewrap** (`bwrap`) for isolated execution, and **util-linux** tools such as `prlimit` and `setpriv`.
- An enabled unprivileged-user-namespace configuration for Bubblewrap. Some hardened systems disable this.
- **Zenity** for graphical local approval dialogs (required to opt in to host mode); optional for foreground key input if using `--terminal-input`.
- The **official OpenAI `tunnel-client`**, installed **separately**, from the source linked above.
- Your **own OpenAI Platform tunnel ID** and a **restricted runtime key** with **Tunnels Read + Use**. Creating/managing the tunnel requires suitable management permission, and ChatGPT custom-MCP access is controlled separately by the ChatGPT workspace.

On **Ubuntu/Debian**, you can install system dependencies with:

```bash
sudo apt update
sudo apt install git python3 python3-venv python3-pip bubblewrap util-linux zenity
```

Use your distribution's package manager elsewhere. The project installer does **not** install system packages, request root access, create a tunnel, start a service or configure ChatGPT for you.

## Installation — foreground (recommended for first use)

### 1. Clone and install the Python dependencies

```bash
git clone https://github.com/0Badwa/linux-terminal-commander.git
cd linux-terminal-commander
./install.sh
```

`install.sh` creates `.venv/` inside this checkout and installs versions from `requirements-lock.txt`. It does **not** modify the existing Ubuntu Commander installation or system services.

### 2. Install the official OpenAI tunnel-client

Follow the [official installation instructions](https://github.com/openai/tunnel-client) for your Linux distribution. Check that the binary works:

```bash
tunnel-client --version
tunnel-client help quickstart
```

The project searches for `tunnel-client` on `PATH`, then `~/.local/bin/tunnel-client`. If your executable is elsewhere, set `LTC_TUNNEL_CLIENT` to its **absolute path** in the environment before running the setup or launcher:

```bash
export LTC_TUNNEL_CLIENT="/absolute/path/to/tunnel-client"
```

The binary is **not** bundled here and has its own license.

### 3. Create your own tunnel and restricted runtime key

In your OpenAI Platform account, create or obtain a **Secure MCP Tunnel** and its tunnel ID. Arrange the required Platform organization / ChatGPT workspace association and permissions as described in the [official onboarding guide](https://github.com/openai/tunnel-client/blob/master/docs/onboarding.md).

- Tunnel management: **Tunnels Read + Manage** (when creating/changing the tunnel).
- Running the tunnel client and selecting it in ChatGPT: **Tunnels Read + Use**.
- ChatGPT custom MCP plugins: the target workspace must permit them.

Use a **restricted runtime key**, not an admin key. **Never paste keys into this repository, GitHub issues, or chat messages.** Obtain the tunnel ID from your own account; no tunnel ID from another user will work as a substitute.

### 4. Configure the local MCP profile

Replace the placeholder below with the **real ID from your own account**:

```bash
.venv/bin/python configure.py --tunnel-id "<YOUR_TUNNEL_ID>"
```

Optionally select an **existing Git checkout** as the primary project:

```bash
.venv/bin/python configure.py --tunnel-id "<YOUR_TUNNEL_ID>" --project "/absolute/path/to/git-project"
```

The configured project must already exist and contain a `.git` checkout. If `--project` is omitted, this repository itself is used.

The configurator calls the official `tunnel-client init` command and creates:

- `profiles/linux-terminal-commander.yaml` — per-user tunnel profile, owner-only.
- `runtime/project-root.txt` — the selected Git project path, owner-only.
- An MCP command pointing to this checkout's `.venv/bin/python` and `server.py`.

It **does not** store your runtime key or start any service. It deliberately **refuses to overwrite** an existing profile/project pointer. Do not simply repeat it against an existing installation.

### 5. Start the tunnel locally

For an interactive terminal prompt (key input hidden):

```bash
.venv/bin/python run_client.py --terminal-input
```

Or, with a graphical desktop and Zenity installed:

```bash
.venv/bin/python run_client.py
```

Enter your restricted runtime key **locally**. The launcher first runs `tunnel-client doctor --explain`; if verification fails, it does not launch the tunnel. On success, the tunnel runs **in the foreground**. Leave that terminal open while using ChatGPT. Press **Ctrl+C** to stop.

**Do not launch a second client for the same profile/tunnel while one is already running.** The optional service and foreground mode are alternatives.

### 6. Connect it in ChatGPT

According to the current [OpenAI Secure MCP Tunnel guide](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels):

1. Open **ChatGPT → Plugins**.
2. Select **+ → Add custom MCP server**.
3. Choose **Connection: Tunnel**.
4. Select your tunnel or enter your tunnel ID; configure authentication, review the warning and create the plugin.
5. Make a safe first call such as **“Show the Linux distribution and current user.”**

The UI and eligibility may differ by account/workspace. If a tunnel is missing, check its **ChatGPT workspace association** and **Tunnels Read + Use** permission. An installed local program alone does not automatically create a ChatGPT plugin.

**Setup is complete only after a real ChatGPT MCP call succeeds.**

## Optional — run as a systemd user service

Do this only **after** foreground operation is confirmed. The service uses a restricted runtime key stored locally for automatic startup. **It will not be enabled by the installer.**

```bash
.venv/bin/python setup_runtime_secret.py --terminal-input
.venv/bin/python install_service.py
systemctl --user daemon-reload
systemctl --user enable --now linux-terminal-commander.service
systemctl --user status linux-terminal-commander.service
```

`setup_runtime_secret.py` requests explicit local confirmation before storing the runtime key in `~/.config/linux-terminal-commander/runtime-api-key` with private file permissions. `install_service.py` creates an owner-controlled user unit at `~/.config/systemd/user/linux-terminal-commander.service`. The systemd template uses `LoadCredential` and `NoNewPrivileges`.

Check logs if startup fails:

```bash
journalctl --user -u linux-terminal-commander.service -n 80 --no-pager
```

Stop/disable the service:

```bash
systemctl --user disable --now linux-terminal-commander.service
```

A login-independent user service may additionally require administrator-approved **lingering**; this project does not change it automatically. The unit generator refuses to overwrite an existing unit. Do not start the service while the foreground client is active.

## Security and permissions

**Default mode: `isolated`.** Linux Terminal Commander starts with offline, disposable **Bubblewrap** terminal execution and bounded file snapshots. This is more restrictive than normal Bash on the host. Some filesystem/Git operations require specific approved roots or local confirmation.

**Host mode: `desktop_compatible` (opt-in).** To enable it, call the MCP configuration tool with the key `approval_mode` and the value `desktop_compatible`, and **approve the local Zenity dialog on the computer**. Only enable this for a fully trusted tunnel/ChatGPT account. The remote assistant can then run Bash with the permissions of your current Linux user, **without per-command approval**. File API guards **do not sandbox** this host shell. Changing back to `isolated` changes the tool's default execution policy; it does not undo prior host-side actions.

Additional safeguards and limits:

- The server refuses to run as root and applies process limits / `no-new-privs` where implemented; this is **not** protection from a malicious command that your normal user is allowed to run.
- Restricted file APIs perform path, symlink, ownership and/or version checks; writes may require explicit local approval.
- Process management can terminate only its **own tracked sessions**, not arbitrary PIDs through those APIs.
- Each runtime uses a **private, user-specific** tunnel profile. No inbound network listener is published by this project.
- **Never commit** `.venv/`, `profiles/`, `runtime/`, `workspace/`, `approved_roots.json`, stored keys, or generated logs. These locations are ignored by Git.
- Do not share your tunnel ID indiscriminately; treat runtime keys and ChatGPT access as sensitive. Remove/revoke the tunnel association or credentials if access is compromised.
- Terminal output, repository text and external files can contain untrusted instructions. User approval and normal security judgment still matter.

## Configuration and local files

| Location | Purpose |
| --- | --- |
| `server.py` | Python MCP server entry point (stdio). |
| `api.py`, `commander_api.py` | MCP tool registration. |
| `configure.py`, `settings.py` | Per-installation profile and selected project. |
| `install.sh`, `requirements-lock.txt` | Python virtual environment and pinned dependencies. |
| `run_client.py` | Foreground tunnel launcher and interactive key input. |
| `setup_runtime_secret.py`, `install_service.py` | Optional owner-only key setup and systemd unit generator. |
| `profiles/`, `runtime/`, `workspace/` | **Private, generated, not for Git.** |
| `~/.config/linux-terminal-commander/` | Optional owner-only runtime-key storage. |

Default configuration is **isolated**; session limit is **2**, default command timeout **300 seconds**, and idle timeout **900 seconds**. These are implementation defaults, not service-level guarantees. The `get_config` MCP tool reports active settings. Specific additional roots and write scopes are explicitly governed by local rules; see source and tool descriptions.

This program does **not** need Codex to run. Some optional tool names are preserved from earlier development work; using them is not required for terminal/file/Git workflows.

## Updating an existing installation

From inside your Linux Terminal Commander checkout:

```bash
git status --short --branch
git pull --ff-only
./install.sh
```

Review local changes **before** updating. Do not overwrite private profiles or change running services automatically. For an explicitly enabled user service, review any changed template and restart it yourself when appropriate. Avoid running two tunnel clients simultaneously.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| `python3: No module named venv` | Install your distribution's `python3-venv` package, then run `./install.sh`. |
| Missing `tunnel-client` executable | Install the **official** binary; verify `tunnel-client --version` or set `LTC_TUNNEL_CLIENT` to its absolute path. |
| `configure.py` says profile/project already exists | An installation may already be configured. Inspect `profiles/` and `runtime/project-root.txt` locally; **do not overwrite them blindly**. |
| `doctor` fails | Check the restricted runtime key, tunnel ID, profile and workspace/organization permissions; follow official tunnel-client diagnostics. |
| Tunnel absent in ChatGPT | Verify custom-MCP eligibility, target workspace association and Tunnels Read + Use. |
| Isolated terminal cannot start | Check `bwrap`, user namespaces and sandbox restrictions. Host mode is **not** an automatic fallback. |
| Local host-mode approval unavailable | A graphical desktop session with Zenity is required for local approval. Do not bypass it using code modifications. |
| Service does not start | Use `systemctl --user status ...` and `journalctl --user -u linux-terminal-commander.service -n 80 --no-pager`. Check file permissions and that another client is not already using the profile. |

If reporting a bug, provide **sanitized** OS details, version/commit, steps to reproduce and redacted error output. Never publish API keys, local private files or tunnel profiles.

## Tests and release status

```bash
.venv/bin/python -m compileall -q .
.venv/bin/python -m unittest -q test_server test_phase2 test_phase3 test_phase4 test_phase5 test_phase51 test_portability
```

At the documented development snapshot: **132/132 automated tests passed** on the original Ubuntu development machine, Python syntax checks passed, the dependency installer ran successfully, and a **test tunnel profile** was generated. A fully authenticated end-to-end installation on another Linux user/computer and multi-distribution compatibility **remain unverified**. The repository is therefore **not yet labeled a stable 1.0 release**.

## License, privacy and upstream references

- **[MIT license](LICENSE)** covers the code in this repository.
- The **official OpenAI `tunnel-client`** is separate software under its own [license](https://github.com/openai/tunnel-client/blob/master/LICENSE). It is not vendored or shipped here.
- **[Secure MCP Tunnel documentation](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels)** — networking, access and ChatGPT connection.
- **[Official tunnel-client onboarding](https://github.com/openai/tunnel-client/blob/master/docs/onboarding.md)** — installation and diagnostics.

Linux Terminal Commander is an **independent open-source project** and is **not an official OpenAI product**. There is no shared service or hosted relay provided by this project. Provider/platform costs or access rules, if applicable, are separate from this repository.
