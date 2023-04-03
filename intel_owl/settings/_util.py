# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import grp
import os
import pwd

# placeholder for later
from pathlib import Path

get_secret = os.environ.get

uid = pwd.getpwnam("www-data").pw_uid
gid = grp.getgrnam("www-data").gr_gid


def set_permissions(directory: Path):
    if not directory.exists():
        raise RuntimeError(f"Directory {directory} does not exists")
    os.chown(directory, uid, gid)
    for path in directory.rglob("*"):
        os.chown(path, uid, gid)
