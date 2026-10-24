# Linux Terminal Commander

Linux Terminal Commander is a **self-hosted Linux MCP server** for ChatGPT. It supports file browsing and editing, Git operations, bounded searches, terminal commands, job status and terminal sessions (39 tools). It is built with Python and the official OpenAI `tunnel-client`. Each installation uses **its own** tunnel and credentials; there is no shared server, account or hosted relay in this repository.

**Status:** development release. Tested on Ubuntu 24.04; other Linux distributions have not been independently verified. Desktop-compatible host access is powerful and is disabled by default. Review the security section before use. This project is independent of and not endorsed by OpenAI.

## Prerequisites

- Linux (Python 3.12 recommended), Git, `python3-venv`, `util-linux` (`prlimit` and `setpriv`), `bubblewrap` (`bwrap`), and `pip` through your venv. `zenity` is optional for desktop dialogs and required to locally authorize host mode.
- The official [`tunnel-client`](https://github.com/openai/tunnel-client) executable, installed separately and available on `PATH` or in `~/.local/bin/tunnel-client`. Do not use an untrusted third-party binary.
- Your own OpenAI tunnel ID and restricted **runtime** API key with **Tunnels Read + Use**, created in the [OpenAI Platform Tunnels](https://platform.openai.com/settings/organization/tunnels) interface. Do not use an admin key for the running service.

On Debian/Ubuntu, system packages are typically installed with `sudo apt install python3 python3-venv python3-pip git bubblewrap zenity`. On other distributions, use the equivalent package manager. Packages are **not** installed automatically by this repository.

## Quick start: private foreground tunnel

```bash
git clone https://github.com/0Badwa/linux-terminal-commander.git
cd linux-terminal-commander
./install.sh
# Install the official tunnel-client following its own published instructions.
# Create your own OpenAI tunnel and restricted runtime key.
.venv/bin/python configure.py --tunnel-id tunnel_YOUR_OWN_32_CHARACTER_ID
.venv/bin/python run_client.py --terminal-input
```

The placeholder tunnel ID above must be replaced with the real ID (and correct syntax) from your account. For a different project Git checkout, configure with `--project /absolute/path/to/project`. The clone itself is the default Git project. The configurator refuses existing tunnel profiles rather than overwriting them. When prompted, type your restricted key privately into the terminal. The foreground process stops with Ctrl+C.

The configurator calls `tunnel-client init --sample sample_mcp_stdio_local`, with an MCP command pointing to this installation's own `.venv/bin/python` and `server.py`. It creates a per-user profile in `profiles/` and stores only the selected project path in `runtime/`. No key is stored by `configure.py`. See the [official onboarding guide](https://github.com/openai/tunnel-client/blob/master/docs/onboarding.md) for permissions and tunnel registration, then add the connector in ChatGPT using your **own** tunnel ID. The tunnel is outbound; there is no need to open a public TCP port on the computer.

For graphical foreground key input, omit `--terminal-input` (requires `zenity`). To run without a tunnel for a local MCP client, launch `.venv/bin/python server.py` over stdio.

## Optional: user service (starts only if you explicitly enable it)

```bash
.venv/bin/python setup_runtime_secret.py --terminal-input
.venv/bin/python install_service.py
systemctl --user daemon-reload
systemctl --user enable --now linux-terminal-commander.service
systemctl --user status linux-terminal-commander.service
```

The first command explicitly stores **your** restricted key in a user-owned private file. `install_service.py` creates a `systemd --user` unit with a systemd `LoadCredential` reference and local `NoNewPrivileges` restrictions. It does **not** enable, start, restart, or replace any running service. To stop: `systemctl --user disable --now linux-terminal-commander.service`. Automatic startup after log-out may require an administrator-approved lingering setting. Avoid running the foreground client and the user service against the same tunnel simultaneously.

Never commit `profiles/`, `runtime/`, `.venv/`, local root enrollments or credential files. They are excluded by `.gitignore`.

## Security model

- **Default isolated mode:** terminal execution uses an offline disposable Bubblewrap sandbox with bounded file snapshots. No unrestricted access to your machine is granted without local activation. Linux distributions need functioning unprivileged user namespaces for this feature.
- **Host mode (opt-in):** `set_config_value(approval_mode=desktop_compatible)` requires a local Zenity confirmation. **After activation, trusted remote callers have full Bash access as your Linux user, without a dialog for every command.** A safety warning or filename filter is not a shell sandbox. Use only with a ChatGPT account and tools you trust.
- The service refuses root execution and disables setuid privilege elevation; this does **not** protect user-readable private files from a remote user-level shell. Do not share tunnel credentials. Limit exposure to your own ChatGPT account and revoke access if compromised.
- File APIs reject protected names, symlinks, unsafe writes and version mismatches; the shell can still read or write any normal file permitted by the Linux user **when host mode is active**.
- The optional stored runtime key is private to the owner; no example tunnel, key or host-specific configuration is bundled.

## Development and tests

Run syntax checks and the fixture-based test suite in your own virtual environment:

```bash
.venv/bin/python -m compileall -q .
.venv/bin/python -m unittest -q test_server test_phase2 test_phase3 test_phase4 test_phase5 test_phase51 test_portability
```

Some integration tests require Bubblewrap, pseudo-terminals, Linux process namespaces and (optionally) the official tunnel client. A clean package installation and a live tunnel connection should also be verified manually on each supported distribution before production use.

## License

MIT for the files in this repository. The independently distributed official OpenAI `tunnel-client` has its own license and release terms; it is **not** included here.
