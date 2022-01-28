from radiusauth.backends import RADIUSRealmBackend

from configuration.radius_config import GET_SERVER_CUSTOMISED, custom_get_server


class CustomRADIUSBackend(RADIUSRealmBackend):
    def get_server(self, realm):
        if GET_SERVER_CUSTOMISED:
            return custom_get_server(self, realm)
        else:
            return super(CustomRADIUSBackend, self).get_server(realm)
