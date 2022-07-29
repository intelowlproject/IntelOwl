from authlib.integrations.django_client import OAuth

from intel_owl import secrets

AUTHLIB_OAUTH_CLIENTS = {
    "google": {
        "client_id": secrets.get_secret("GOOGLE_CLIENT_ID"),
        "client_secret": secrets.get_secret("GOOGLE_CLIENT_SECRET"),
    }
}

GOOGLE_CONF_URL = "https://accounts.google.com/.well-known/openid-configuration"
oauth = OAuth()
oauth.register(
    name="google",
    server_metadata_url=GOOGLE_CONF_URL,
    client_kwargs={"scope": "openid email profile"},
)
