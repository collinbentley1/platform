import os
import re
import shutil
import sys
import tarfile
from pathlib import Path

archive, destination = map(Path, sys.argv[1:])
if destination.exists() or destination.is_symlink():
    raise SystemExit("OCI destination already exists")
with tarfile.open(archive, "r:") as source:
    members = source.getmembers()
    if len(members) > 520 or sum(member.size for member in members) > 1610612736:
        raise SystemExit("OCI archive exceeds bounds")
    paths = set()
    for member in members:
        name = member.name.removeprefix("./").rstrip("/")
        valid_dir = member.isdir() and name in ("", "blobs", "blobs/sha256")
        valid_file = member.isfile() and (name in ("index.json", "oci-layout") or re.fullmatch(r"blobs/sha256/[a-f0-9]{64}", name))
        if name in paths or not (valid_dir or valid_file) or member.size < 0:
            raise SystemExit("OCI archive contains an invalid entry")
        paths.add(name)
    (destination / "blobs/sha256").mkdir(parents=True, mode=0o700)
    for member in members:
        if member.isfile():
            name = member.name.removeprefix("./")
            with source.extractfile(member) as incoming, (destination / name).open("xb") as output:
                shutil.copyfileobj(incoming, output, length=1024 * 1024)
