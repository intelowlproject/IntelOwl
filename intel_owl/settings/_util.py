import grp
import os
import pwd
from pathlib import PosixPath

# placeholder for later
get_secret = os.environ.get

uid = pwd.getpwnam("www-data").pw_uid
gid = grp.getgrnam("www-data").gr_gid


def touch(path):
    with open(path, "a", encoding="utf-8") as file_pointer:
        file_pointer.close()


def set_permissions(directory):
    from .commons import STAGE_CI

    if STAGE_CI:
        return
    directory = PosixPath(directory)
    if directory.exists():
        os.chown(directory, uid, gid)
    for file in directory.rglob("*"):
        os.chown(file, uid, gid)
