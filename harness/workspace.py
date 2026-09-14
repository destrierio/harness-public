"""A run scratch directory shared with the shell/session tools. `fetch` pulls a
target file or binary in and registers it in the KB, so the pwn specialist can
operate on artifacts (checksec, gdb, pwntools) that persist across turns."""
from __future__ import annotations

import hashlib
import os
import tempfile

from .kb import Artifact


class Workspace:
    def __init__(self, root: str | None = None) -> None:
        if root:
            self.root = root
        elif os.path.isdir("/workspace"):
            self.root = "/workspace"
        else:
            self.root = tempfile.mkdtemp(prefix="dh-workspace-")
        os.makedirs(self.root, exist_ok=True)

    def path(self, name: str) -> str:
        safe = os.path.basename(name) or "artifact"
        return os.path.join(self.root, safe)

    def write_bytes(self, name: str, data: bytes) -> str:
        target = self.path(name)
        with open(target, "wb") as fh:
            fh.write(data)
        return target

    def register_path(self, path: str, source: str = "") -> Artifact:
        with open(path, "rb") as fh:
            data = fh.read()
        return Artifact(
            name=os.path.basename(path),
            path=path,
            sha256=hashlib.sha256(data).hexdigest(),
            source=source or path,
        )

    def fetch_url(self, url: str, http_client, name: str | None = None) -> Artifact:
        status, data = http_client.get_bytes(url)
        if status == 0 or not data:
            raise OSError(f"could not fetch {url} (status {status})")
        name = name or os.path.basename(url.split("?")[0]) or "artifact"
        target = self.write_bytes(name, data)
        return Artifact(
            name=os.path.basename(target),
            path=target,
            sha256=hashlib.sha256(data).hexdigest(),
            source=url,
        )
