"""Additional tools; all original root-based contracts remain unchanged."""
from functools import wraps
import asyncio
from mcp.types import ToolAnnotations
from mcp.server.mcpserver.exceptions import ToolError
from commander_policy import Policy
from commander_files import PathFiles
from commander_processes import Processes
from security import Denied, nonroot, redact


def register_commander(mcp, paths, approval):
    policy = Policy(paths, approval)
    files = PathFiles(policy)
    processes = Processes(policy)

    def tool(read_only=False):
        def decorate(fn):
            @wraps(fn)
            async def guarded(*args, **kwargs):
                nonroot()
                try:
                    # Search cancellation/status must remain responsive while a
                    # foreground shell or local approval is waiting.
                    return await asyncio.to_thread(fn, *args, **kwargs)
                except Denied as exc:
                    raise ToolError(redact(str(exc))) from None
                except FileExistsError:
                    raise ToolError('Destination already exists; nothing overwritten.') from None
                except FileNotFoundError:
                    raise ToolError('Path/session unavailable or changed; inspect current state.') from None
                except PermissionError:
                    raise ToolError('OS permission denied; no elevated-user fallback.') from None
                except Exception:
                    raise ToolError('Commander operation failed safely; no automatic retry.') from None
            return mcp.tool(annotations=ToolAnnotations(read_only_hint=read_only,
                destructive_hint=not read_only, idempotent_hint=read_only,
                open_world_hint=fn.__name__ in ('exec_command', 'start_process')))(guarded)
        return decorate

    @tool(True)
    def get_config() -> dict:
        """Read active host/isolated mode, one-time consent, exact-command approval and filesystem policy. No secrets or environment values."""
        return policy.describe()

    @tool()
    def set_config_value(key: str, value: str | int | list[dict]) -> dict:
        """Locally approve and audit a durable preference. Keys: default_cwd, session_limit (1..4), default_timeout (1..3600), idle_timeout (10..3600), approval_mode (isolated/desktop_compatible; trusted_local_dev/trusted aliases), advisory_guards (informational path_prefix/command_pattern objects), approved_project_scopes (objects path/write/trusted_terminal). Never silently weakens protection."""
        return policy.set(key, value)

    @tool(True)
    def read_file_path(path: str, start_line: int=1, end_line: int=120) -> dict:
        """Read a canonical UTF-8 path (real host paths after one-time activation), <=1 MiB/file, <=200 lines and 64 KiB output, with opaque version. No symlinks/protected files."""
        return files.read(path, start_line, end_line)

    @tool(True)
    def read_multiple_files(paths: list[str]) -> dict:
        """Read 1..16 development files, 80 lines each, <=64 KiB combined; no automatic secret summaries."""
        return files.multiple(paths)

    @tool()
    def write_file_path(path: str, content: str, mode: str='create', expected_version: str='') -> dict:
        """Create (no overwrite), atomic replace or append in scratch/authorized scope or real host paths after one-time activation. Replace/append require the exact current version. No local popup after project/host consent."""
        return files.write(path, content, mode, expected_version)

    @tool()
    def edit_block_path(path: str, old_text: str, new_text: str, expected_version: str) -> dict:
        """Versioned atomic exact-one-match text edit in authorized project scopes; preserves permissions."""
        return files.edit(path, old_text, new_text, expected_version)

    @tool()
    def create_directory(path: str) -> dict:
        """Create one absent 0700 directory in an authorized scope; parent must exist. No recursive filesystem changes."""
        return files.mkdir(path)

    @tool(True)
    def list_directory_path(path: str, offset: int=0, limit: int=100) -> dict:
        """Bounded sorted path listing; <=200 entries/page, <=20000 scanned, continuation offset. Excludes symlinks/secrets; isolated policy also excludes generated/cache trees."""
        return files.listing(path, offset, limit)

    @tool()
    def move_path(src: str, dst: str, expected_version: str) -> dict:
        """Atomically move/rename one versioned regular UTF-8 file between authorized scopes, without overwriting. Directory moves/deletes are not exposed."""
        return files.move(src, dst, expected_version)

    @tool(True)
    def get_file_info(path: str) -> dict:
        """Read text-file size, mode, mtime and opaque version without content."""
        return files.info(path)

    @tool(True)
    def search_paths(paths: list[str], pattern: str, kind: str='text', regex: bool=False, file_glob: str='*', offset: int=0, limit: int=50, max_depth: int=8, search_id: str='') -> dict:
        """Search 1..8 project paths for text or filename globs. Linear-time ripgrep regex, <=3s/10000 entries/depth12/1MiB files/100 matches. Offset rescan pagination; use a caller-generated 32-hex search_id to cancel concurrently. Narrow scope if scan budget exhausted."""
        return files.search(paths, pattern, kind, regex, file_glob, offset, limit, max_depth, search_id)

    @tool()
    def cancel_search(search_id: str) -> dict:
        """Request cancellation of a bounded in-flight search by caller-chosen 32-hex ID. Never accepts PIDs."""
        return files.cancel_search(search_id)

    @tool()
    def exec_command(command: str, cwd: str, timeout_seconds: int | None=None, max_output_bytes: int=16384, mode: str='auto', approval_hint: str='') -> dict:
        """Real /usr/bin/bash command (pipes/redirections/globs/scripts). Explicit cwd; foreground <=30s, <=16KiB output, exit status/streams/truncation. Default auto follows configured mode. After ONE local desktop_compatible activation, Bash uses the real host/cwd without command dialogs. Explicit isolated uses offline /work. approval_hint cannot authorize anything. Poll returned session ID if detached."""
        return processes.execute(command, cwd, timeout_seconds, max_output_bytes, mode, approval_hint)

    @tool()
    def start_process(command: str, cwd: str, pty: bool=False, timeout_seconds: int | None=None, mode: str='auto', approval_hint: str='') -> dict:
        """Detach a real Bash job immediately (1..3600s TTL), optionally PTY. Default auto follows configured host/isolated mode; explicit isolated remains available. Bounded private logs, concurrency and idle TTL; no implicit retry."""
        return processes.start(command, cwd, pty, timeout_seconds, mode, approval_hint)

    @tool(True)
    def process_status(session_id: str) -> dict:
        """Poll a tracked session: state, PID/process group, exit code, TTL, stream offsets. Lost supervisors are orphaned with unknown outcome, never falsely completed."""
        return processes.status(session_id)

    @tool(True)
    def read_process_output(session_id: str, offset: int=0, limit: int=8192) -> dict:
        """Read stream-tagged output by absolute UTF-8 byte offset (<=16KiB); 128KiB rolling redacted logs, dropped-prefix/truncation indicators."""
        return processes.output(session_id, offset, limit)

    @tool()
    def interact_with_process(session_id: str, input: str='', read_budget: int=8192) -> dict:
        """Send <=4096 UTF-8 bytes to a known session pipe/PTY and read bounded output immediately. No passwords/secrets. Partial input errors must not be retried blindly."""
        return processes.interact(session_id, input, read_budget)

    @tool(True)
    def list_sessions() -> dict:
        """List at most 30 tracked session records and current outcomes; no raw command lines or environment values."""
        return processes.list()

    @tool()
    def terminate_process(session_id: str) -> dict:
        """Cancel only an owned tracked session and its process group. Arbitrary system/unrelated PIDs are never accepted."""
        return processes.terminate(session_id)

    @tool(True)
    def list_processes(filter: str='', limit: int=100) -> dict:
        """List <=200 current-user process names/PIDs/parents/states; filter names only, never cmdline or environ. Termination is limited to tracked session IDs."""
        return processes.processes(filter, limit)

    return policy, files, processes
