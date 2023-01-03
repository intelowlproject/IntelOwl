# certego_saas
from .security import WEB_CLIENT_URL

HOST_URI = WEB_CLIENT_URL
HOST_NAME = "IntelOwl"
CERTEGO_SAAS = {
    "USER_ACCESS_SERIALIZER": "authentication.serializers.UserAccessSerializer"
}
