"""Phase 2 tools registered on the existing Phase 1 MCP server."""
from functools import wraps
from pathlib import Path

from mcp.types import ToolAnnotations
from mcp.server.mcpserver.exceptions import ToolError
from codex_prompts import save_prompt
from files import Files
from gitops import Git,BRANCH
from jobs import Jobs
from security import Approval, Denied, Paths, nonroot, redact


def register(mcp,project,workspace,root_config=None):
    paths=Paths(project,workspace,root_config=root_config)
    approval=Approval()
    git=Git(paths,approval)
    files=Files(paths,approval,lambda root:bool(BRANCH.fullmatch(git.state(root)['branch'] or '')))
    jobs=Jobs(paths,approval,git)
    def tool(read_only):
        def decorator(fn):
            @wraps(fn)
            def guarded(*args,**kwargs):
                nonroot()
                try:
                    return fn(*args,**kwargs)
                except Denied as exc:
                    raise ToolError(redact(str(exc))) from None
                except Exception:
                    # SDK errors must not expose subprocess args, config, or raw file contents.
                    raise ToolError('Operation failed safely; inspect approved inputs and current state.') from None
            return mcp.tool(annotations=ToolAnnotations(read_only_hint=read_only,
                destructive_hint=fn.__name__ in ('edit_text_file','cancel_job'),
                idempotent_hint=read_only,open_world_hint=False))(guarded)
        return decorator

    @tool(True)
    def permitted_roots() -> dict:
        """List approved root IDs. Use root IDs and relative paths in all file tools."""
        return files.roots()

    @tool(True)
    def list_directory(root: str='project',path: str='.',limit: int=100) -> dict:
        """List at most 200 entries; excludes protected paths and symlinks."""
        return files.listing(root,path,limit)

    @tool(True)
    def read_file(root: str,path: str,start_line: int=1,end_line: int=120) -> dict:
        """Read at most 200 UTF-8 text lines and return the exact opaque file version."""
        return files.read(root,path,start_line,end_line)

    @tool(True)
    def search_files(root: str,pattern: str,file_pattern: str='*',path: str='.',limit: int=50) -> dict:
        """Bounded literal text search with a basename glob. No regex or shell patterns."""
        return files.search(root,pattern,file_pattern,path,limit)

    @tool(True)
    def file_metadata(root: str,path: str) -> dict:
        """Get bounded text file size, mode, modification timestamp, and opaque version."""
        return files.metadata(root,path)

    @tool(False)
    def create_text_file(root: str,path: str,content: str) -> dict:
        """Create an absent text file after one local human approval. Never overwrites."""
        return files.create(root,path,content)

    @tool(False)
    def save_codex_prompt(filename: str,content: str) -> dict:
        """Save a new UTF-8 Markdown Codex task in /tmp/romans-codex-prompts without a local dialog. Explicitly preauthorized only for this directory; safe .md basename, 256 KiB maximum, no overwrite or execution. Returns verified path, byte count and SHA-256."""
        return save_prompt(filename,content)

    @tool(False)
    def edit_text_file(root: str,path: str,expected_version: str,old_text: str,new_text: str) -> dict:
        """Replace exactly one old-text match after version checks and local approval."""
        return files.edit(root,path,expected_version,old_text,new_text)

    @tool(True)
    def git_read(root: str='project',operation: str='status',paths: list[str]|None=None,
                 revision: str='HEAD',limit: int=10,staged: bool=False) -> dict:
        """Structured status/log/diff/show/branch/rev_parse/diff_check. Diffs require explicit safe file paths."""
        return git.read(root,operation,paths,revision,limit,staged)

    @tool(False)
    def git_create_branch(name: str,expected_head: str) -> dict:
        """Create a new codex branch without switching the checkout; local approval required."""
        return git.create_branch(name,expected_head)

    @tool(False)
    def git_create_worktree(name: str,expected_head: str) -> dict:
        """Create a new codex branch and worktree in the fixed managed directory, after local approval."""
        return git.create_worktree(name,expected_head)

    @tool(False)
    def git_commit(root: str,expected_head: str,message: str,versions: dict[str,str],
                   author_name: str='',author_email: str='') -> dict:
        """Commit 1..20 explicitly versioned files on a managed codex worktree; clean index and local approval required."""
        return git.commit(root,expected_head,message,versions,author_name,author_email)

    @tool(False)
    def start_job(task: str,root: str='project',tests: list[str]|None=None,
                  paths: list[str]|None=None,expected_head: str='',timeout: int=300) -> dict:
        """Start core_test, desktop_classes, diff_check, git_fetch or git_push. No command strings. Gradle/fetch/push require local approval."""
        return jobs.start(task,root,tests,paths,expected_head,timeout)

    @tool(True)
    def job_status(job_id: str) -> dict:
        """Poll one job's state and limits without waiting for completion."""
        return jobs.status(job_id)

    @tool(True)
    def job_output(job_id: str,offset: int=0,limit: int=8192) -> dict:
        """Read at most 16 KiB from a redacted 128 KiB retained log window."""
        return jobs.output(job_id,offset,limit)

    @tool(False)
    def cancel_job(job_id: str) -> dict:
        """Request cancellation of exactly one known active job and its isolated process tree."""
        return jobs.cancel(job_id)

    from commander_api import register_commander
    register_commander(mcp, paths, approval)
    return paths,files,git,jobs
