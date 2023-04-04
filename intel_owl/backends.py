# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from radiusauth.backends import RADIUSRealmBackend

from configuration.radius_config import GET_SERVER_CUSTOMISED, custom_get_server


class CustomRADIUSBackend(RADIUSRealmBackend):
    def get_server(self, realm):
        if GET_SERVER_CUSTOMISED:
            return custom_get_server(self, realm)
        else:
            return super().get_server(realm)
