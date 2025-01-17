# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import grp
import logging
import os
import pwd

# placeholder for later
from pathlib import Path

logger = logging.getLogger(__name__)

get_secret = os.environ.get

uid = pwd.getpwnam("www-data").pw_uid
gid = grp.getgrnam("www-data").gr_gid


def set_permissions(directory: Path, force_create: bool = False):
    if not directory.exists():
        # this may happen in case we have added a new directory in the Dockerfile
        # but the image has been already built by the user -> see "blint" directory case
        if force_create:
            os.mkdir(directory)
        else:
            raise RuntimeError(f"Directory {directory} does not exists")
    logger.info(f"setting permissions for {directory}")
    os.chown(directory, uid, gid)
    for path in directory.rglob("*"):
        os.chown(path, uid, gid)
