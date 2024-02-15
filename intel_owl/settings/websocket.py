from intel_owl import secrets

websockets_url = secrets.get_secret("WEBSOCKETS_URL", None)
if not websockets_url:
    raise RuntimeError("Unable to configure websockets")
ASGI_APPLICATION = "intel_owl.asgi.application"
CHANNEL_LAYERS = {
    "default": {
        "BACKEND": "channels_redis.core.RedisChannelLayer",
        "CONFIG": {
            "hosts": [f"{websockets_url}/0"],
        },
    },
}
