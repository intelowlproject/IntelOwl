# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from authlib.integrations.django_client import OAuth
from django.conf import settings

oauth = OAuth()
if "google" in settings.AUTHLIB_OAUTH_CLIENTS:
    GOOGLE_CONF_URL = "https://accounts.google.com/.well-known/openid-configuration"
    oauth.register(
        name="google",
        server_metadata_url=GOOGLE_CONF_URL,
        client_kwargs={"scope": "openid email profile"},
    )
