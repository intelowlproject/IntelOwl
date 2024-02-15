from intel_owl import secrets
import socket

websockets_url = secrets.get_secret("WEBSOCKETS_URL", None)
if not websockets_url:
    if socket.gethostname() in ["uwsgi", "daphne"]:
        raise RuntimeError("Unable to configure websockets")
else:
    ASGI_APPLICATION = "intel_owl.asgi.application"
    CHANNEL_LAYERS = {
        "default": {
            "BACKEND": "channels_redis.core.RedisChannelLayer",
            "CONFIG": {
                "hosts": [f"{websockets_url}/0"],
            },
        },
    }
