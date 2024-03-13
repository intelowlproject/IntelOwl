import socket

from intel_owl import secrets

websockets_url = secrets.get_secret("WEBSOCKETS_URL", "redis://redis:6379/0")
if not websockets_url:
    if socket.gethostname() in ["uwsgi", "daphne"]:
        raise RuntimeError("Unable to configure websockets. Please set WEBSOCKETS_URL")
else:
    ASGI_APPLICATION = "intel_owl.asgi.application"
    CHANNEL_LAYERS = {
        "default": {
            "BACKEND": "channels_redis.core.RedisChannelLayer",
            "CONFIG": {
                "hosts": [websockets_url],
            },
        },
    }
