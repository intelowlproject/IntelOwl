# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.


from ..classes import Connector


class MISP(Connector):
    def run(self):
        return {"success": True}
