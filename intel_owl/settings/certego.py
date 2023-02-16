# certego_saas
from .security import WEB_CLIENT_URL

HOST_URI = WEB_CLIENT_URL
HOST_NAME = "IntelOwl"
CERTEGO_SAAS = {
    "USER_ACCESS_SERIALIZER": "authentication.serializers.UserAccessSerializer",
    "HOST_URI": HOST_URI,
    "HOST_NAME": HOST_NAME,
}
