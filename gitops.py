"""Structured Git operations. No raw argv, hooks, credential helpers, or main writes."""
import configparser
import hashlib
import json
import os
from pathlib import Path
import re

from execution import capture, sandbox
from security import Denied, argument, relative


BRANCH = re.compile(r'codex/[a-z0-9][a-z0-9-]{0,62}\Z')
OID = re.compile(r'[0-9a-f]{40}\Z')
REF = re.compile(r'(?:HEAD(?:~[0-9]{1,3})?|[0-9a-f]{7,40}|(?:origin/)?codex/[a-z0-9][a-z0-9-]{0,62}|(?:origin/)?main)\Z')
GIT = ['/usr/bin/git','--no-pager','--literal-pathspecs',
       '-c','core.hooksPath=/dev/null','-c','core.fsmonitor=false',
       '-c','core.pager=cat','-c','credential.helper=', '-c','credential.interactive=false',
       '-c','core.quotePath=false',
       '-c','diff.external=', '-c','core.attributesFile=/dev/null',
       '-c','filter.lfs.required=false', '-c','core.sshCommand=/usr/bin/false',
       '-c','protocol.file.allow=never','-c','protocol.ext.allow=never',
       '-c','protocol.ssh.allow=never','-c','protocol.https.allow=always',
       '-c','commit.gpgSign=false','-c','push.gpgSign=false']


def ref(value):
    argument(value)
    if not REF.fullmatch(value):
        raise Denied('Use HEAD, HEAD~N, a commit id, main, or a codex branch.')
    return value


class Git:
    def __init__(self,paths,approval):
        self.paths,self.approval=paths,approval
        self._restore_worktrees()

    def _layout(self,root):
        return self.paths.git_layout(root)

    def _config(self, common):
        """Replace repository config inside the sandbox with inert selected values."""
        config=common/'config'
        if config.is_symlink() or config.stat().st_size>65536:
            raise Denied('Unsafe Git config.')
        parser=configparser.RawConfigParser(strict=False)
        try:
            parser.read_string(config.read_text())
        except (configparser.Error,UnicodeError):
            raise Denied('Unsupported Git config syntax.') from None
        def value(section,key):
            result=parser.get(section,key,fallback='').strip().strip('"')
            if '\n' in result or '\r' in result or '\\' in result or '"' in result:
                raise Denied('Unsupported Git config value.')
            return result
        selected={'name':value('user','name'),'email':value('user','email'),
                  'url':value('remote "origin"','url'),'pushurl':value('remote "origin"','pushurl')}
        # Existing config commands, includes, URL rewrites, proxies, HTTP headers,
        # filters and credential helpers never reach any Git subprocess.
        text='[core]\n\trepositoryformatversion = 0\n\tbare = false\n\tlogallrefupdates = true\n'
        if selected['name'] and selected['email']:
            name=argument(selected['name'],120)
            email=selected['email']
            if not re.fullmatch(r'[A-Za-z0-9_.+%-]+@[A-Za-z0-9.-]+',email):
                raise Denied('Unsupported local Git identity.')
            text+='[user]\n\tname = '+name+'\n\temail = '+email+'\n'
        target=self.paths.workspace/('git-config-'+hashlib.sha256(text.encode()).hexdigest())
        if not target.exists():
            fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            with os.fdopen(fd,'w') as f:
                f.write(text)
        elif target.is_symlink() or target.read_text()!=text:
            raise Denied('Safe Git config was modified locally.')
        return target,selected

    def command(self,root,args,write=False,network=False):
        if write:
            self.paths.git_writable(root)
        repo,common=self._layout(root)
        mounts=[(repo,repo,write)]
        if not common.is_relative_to(repo):
            mounts.append((common,common,write))
        config,_=self._config(common)
        mounts.append((config,common/'config',False))
        return sandbox(mounts,repo,[*GIT,*args],network=network)

    def run(self,root,args,write=False,timeout=15):
        result=capture(self.command(root,args,write=write),timeout=timeout)
        if result['returncode']:
            raise Denied('Git operation failed: '+result['output'][:2000])
        return result

    def state(self,root):
        head=self.run(root,['rev-parse','--verify','HEAD'])['output'].strip()
        branch=self.run(root,['branch','--show-current'])['output'].strip()
        if not OID.fullmatch(head):
            raise Denied('Invalid repository HEAD.')
        return {'head':head,'branch':branch or None}

    def _paths(self,paths):
        if not 1<=len(paths)<=20:
            raise Denied('Provide 1..20 explicit non-sensitive file paths.')
        for p in paths:
            relative(p)
        return paths

    def read(self,root,operation,paths=None,revision='HEAD',limit=10,staged=False):
        paths=paths or []
        if not 1<=limit<=50:
            raise Denied('Git log limit must be 1..50.')
        if operation=='status':
            args=['status','--short','--untracked-files=normal','--ignore-submodules=all']
        elif operation=='log':
            args=['log','--no-decorate','--format=%h %ad %s','--date=short',f'-{limit}',ref(revision),'--']
        elif operation=='branch':
            args=['branch','--list','--no-color','--format=%(refname:short) %(objectname:short)']
        elif operation=='rev_parse':
            return self.state(root)
        elif operation=='diff':
            args=['diff','--no-ext-diff','--no-textconv','--ignore-submodules=all']
            if staged:
                args.append('--cached')
            args+=['--',*self._paths(paths)]
        elif operation=='diff_check':
            result=capture(self.command(root,['diff','--check','--no-ext-diff','--no-textconv','--ignore-submodules=all','--',*self._paths(paths)]))
            return result
        elif operation=='show':
            if not paths:
                args=['show','--no-patch','--no-show-signature','--format=fuller',ref(revision),'--']
            else:
                self._paths(paths)
                if len(paths)!=1:
                    raise Denied('Show accepts exactly one file.')
                # Blob-only show prevents historical paths outside the selected path.
                args=['show','--no-ext-diff','--no-textconv',ref(revision)+':'+paths[0]]
        else:
            raise Denied('Git operation is not allowlisted.')
        # File symlinks/hardlinks cannot be followed to bypass file policy.
        if operation in ('diff','diff_check'):
            for path in paths:
                p=self.paths.root(root)/path
                if p.exists() or p.is_symlink():
                    self.paths.read(root,path)
        return self.run(root,args)

    def _expected(self,root,head):
        state=self.state(root)
        if not OID.fullmatch(head) or state['head']!=head:
            raise Denied('HEAD changed; inspect the repository again.')
        return state

    def create_branch(self,name,expected_head):
        if not BRANCH.fullmatch(name):
            raise Denied('Dedicated branches must match codex/<lowercase-slug>.')
        self._expected('project',expected_head)
        self.approval.require('git_create_branch',{'name':name,'expected_head':expected_head})
        with self.paths.lock:
            self._expected('project',expected_head)
            return self.run('project',['branch','--no-track',name,expected_head],write=True)

    def create_worktree(self,name,expected_head):
        if not BRANCH.fullmatch(name):
            raise Denied('Use a new codex/<lowercase-slug> branch.')
        self._expected('project',expected_head)
        destination=self.paths.worktrees/name.split('/')[1]
        if destination.exists() or destination.is_symlink():
            raise Denied('Worktree destination already exists.')
        self.approval.require('git_create_worktree',{'branch':name,'expected_head':expected_head,
                                                   'path':str(destination)})
        with self.paths.lock:
            self._expected('project',expected_head)
            repo,common=self._layout('project')
            config,_=self._config(common)
            command=sandbox([(repo,repo,True),(self.paths.worktrees,self.paths.worktrees,True),
                             (config,common/'config',False)],repo,
                            [*GIT,'worktree','add','--no-track','-b',name,str(destination),expected_head])
            result=capture(command,timeout=30)
            if result['returncode']:
                raise Denied('Worktree creation failed: '+result['output'][:1500])
            root='worktree:'+name.split('/')[1]
            self.paths.roots[root]=destination
            self._save_worktrees()
            return {'root':root,'path':str(destination),'branch':name}

    def _save_worktrees(self):
        entries={k:str(v) for k,v in self.paths.roots.items() if k.startswith('worktree:')}
        target=self.paths.workspace/'managed-worktrees.json'
        temporary=target.with_suffix('.new')
        temporary.write_text(json.dumps(entries))
        temporary.chmod(0o600)
        os.replace(temporary,target)

    def _restore_worktrees(self):
        target=self.paths.workspace/'managed-worktrees.json'
        if not target.exists():
            return
        if target.is_symlink() or target.stat().st_size>16384:
            raise Denied('Invalid managed worktree registry.')
        for name,value in json.loads(target.read_text()).items():
            if not re.fullmatch(r'worktree:[a-z0-9][a-z0-9-]{0,62}',name):
                raise Denied('Invalid managed root id.')
            p=Path(value)
            if p.parent!=self.paths.worktrees or p.name!=name.split(':')[1] or p.resolve()!=p:
                raise Denied('Invalid managed worktree path.')
            if p.is_dir():
                self.paths.roots[name]=p

    def remote(self,root):
        # Read config under the sandbox, never surface a credential-bearing URL.
        _,common=self._layout(root)
        _,selected=self._config(common)
        url=selected['url']
        push=selected['pushurl'] or url
        if url!=push or not re.fullmatch(r'https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?',url):
            raise Denied('Only an existing credential-free GitHub HTTPS origin with matching push URL is supported.')
        return url

    def fetch_plan(self,root,expected_head):
        self.paths.git_writable(root)
        self._expected(root,expected_head)
        url=self.remote(root)
        self.approval.require('git_fetch',{'root':root,'url':url,'expected_head':expected_head})
        self._expected(root,expected_head)
        # Direct validated URL avoids configured remote helpers, rewrites are
        # constrained again by the subprocess protocol allowlist and sandbox.
        args=['-c','http.followRedirects=false','-c','http.extraHeader=',
              'fetch','--no-tags','--no-recurse-submodules',url,
              'refs/heads/*:refs/remotes/origin/*']
        return self.command(root,args,write=True,network=True)

    def commit(self,root,expected_head,message,versions,author_name='',author_email=''):
        branch=self._expected(root,expected_head)['branch'] or ''
        if not root.startswith('worktree:') or not BRANCH.fullmatch(branch):
            raise Denied('Commits are restricted to managed codex worktrees.')
        argument(message,200)
        identity=[]
        if author_name or author_email:
            argument(author_name,120)
            if not re.fullmatch(r'[A-Za-z0-9_.+%-]+@[A-Za-z0-9.-]+',author_email):
                raise Denied('Provide an explicit valid commit identity.')
            identity=['-c','user.name='+author_name,'-c','user.email='+author_email]
        if not 1<=len(versions)<=20:
            raise Denied('Commit needs exact versions for 1..20 task-owned text files.')
        self._paths(list(versions))
        def check():
            if self._expected(root,expected_head)['branch']!=branch:
                raise Denied('Branch changed since review.')
            for path,version in versions.items():
                if self.paths.read(root,path)[1]!=version:
                    raise Denied('File changed since review: '+path)
            if self.run(root,['diff','--cached','--name-only','--'])['output'].strip():
                raise Denied('Index contains pre-existing staged changes; refusing to stage or commit.')
        check()
        self.approval.require('git_commit',{'root':root,'expected_head':expected_head,
                              'message':message,'versions':versions,
                              'author_name':author_name or 'existing repository identity',
                              'author_email':author_email or 'existing repository identity'})
        with self.paths.lock:
            check()
            self.run(root,['add','--',*versions],write=True)
            if self._expected(root,expected_head)['branch']!=branch:
                raise Denied('Branch changed while staging; index preserved for review.')
            expected={}
            for path,version in versions.items():
                text,current,_=self.paths.read(root,path)
                if current!=version:
                    raise Denied('File changed while staging; index preserved for review.')
                data=text.encode()
                expected[path]=hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
            staged=self.run(root,['ls-files','--stage','--'])['output'].splitlines()
            actual={}
            for entry in staged:
                details,path=entry.split('\t',1)
                mode,oid,stage=details.split()
                if path in versions:
                    if stage!='0' or mode not in ('100644','100755'):
                        raise Denied('Unexpected staged file type.')
                    actual[path]=oid
            if actual!=expected:
                raise Denied('Staged content differs from approved versions; index preserved for review.')
            changed=set(self.run(root,['diff','--cached','--name-only','--no-ext-diff','--no-textconv','--'])['output'].splitlines())
            if changed!=set(versions):
                raise Denied('Staged changes are not exactly the approved files; index preserved for review.')
            result=self.run(root,[*identity,'commit','--no-gpg-sign','-m',message],write=True,timeout=30)
            return {**result,**self.state(root)}

    def push_plan(self,root,expected_head):
        state=self._expected(root,expected_head)
        branch=state['branch'] or ''
        if not root.startswith('worktree:') or not BRANCH.fullmatch(branch):
            raise Denied('Push is restricted to managed codex worktrees.')
        url=self.remote(root)
        if self.run(root,['status','--porcelain','--untracked-files=normal','--'])['output'].strip():
            raise Denied('Review and commit worktree changes before pushing.')
        self.approval.require('git_push',{'root':root,'head':expected_head,'branch':branch,'url':url})
        self._expected(root,expected_head)
        return self.command(root,['-c','http.followRedirects=false','-c','http.extraHeader=',
            'push','--no-verify','--porcelain',url,f'{expected_head}:refs/heads/{branch}'],write=True,network=True)
