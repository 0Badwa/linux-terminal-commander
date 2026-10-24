"""Fixed sandbox bootstrap. Called only after structured Gradle validation."""
import os
from pathlib import Path
import shutil
import sys

# Both destinations are size-limited tmpfs mounts. The host source/cache are read only.
shutil.copytree('/source','/work',dirs_exist_ok=True,symlinks=False)
for child in Path('/cache-seed').iterdir():
    if child.name not in ('wrapper','caches'):
        continue
    # Never import init scripts, properties, user credentials, or symlinks.
    for base,dirs,files in os.walk(child,followlinks=False):
        dirs[:]=[d for d in dirs if not (Path(base)/d).is_symlink()]
        dest=Path('/gradle-cache')/Path(base).relative_to('/cache-seed')
        dest.mkdir(parents=True,exist_ok=True)
        for name in files:
            source=Path(base)/name
            if not source.is_symlink() and source.is_file() and source.stat().st_nlink==1:
                shutil.copy2(source,dest/name)
os.chdir('/work')
os.execv(sys.argv[1],sys.argv[1:])
