import grp
import os
import pwd

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
    if os.path.exists(directory):
        stat_file = os.stat(directory)
        if uid != stat_file.st_uid and gid != stat_file.st_gid:
            os.chown(directory, uid, gid)
            if os.path.isdir(directory):
                for file in os.listdir(directory):
                    try:
                        os.chown(os.path.join(directory, file), uid, gid)
                    except PermissionError:
                        pass
            else:
                os.chown(directory, uid, gid)
