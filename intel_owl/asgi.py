import os

from channels.auth import AuthMiddlewareStack
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.security.websocket import AllowedHostsOriginValidator
from django.core.asgi import get_asgi_application
from django.urls import path

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "intel_owl.settings")

# Initialize Django ASGI application early to ensure the AppRegistry
# is populated before importing code that may import ORM models.
get_asgi_application()

# pylint: disable=wrong-import-position
from api_app.websocket import JobConsumer  # noqa: E402
from intel_owl.middleware import WSAuthMiddleware  # noqa: E402

application = ProtocolTypeRouter(
    {
        # websocket protocol routing
        "websocket": AllowedHostsOriginValidator(
            AuthMiddlewareStack(
                WSAuthMiddleware(
                    URLRouter(
                        [
                            path("ws/jobs/<int:job_id>", JobConsumer.as_asgi()),
                        ]
                    )
                )
            )
        ),
    }
)
