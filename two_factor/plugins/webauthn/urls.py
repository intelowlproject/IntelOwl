from django.urls import path

from .views import CreateCredentialJS, GetCredentialJS

app_name = "webauthn"

urlpatterns = [
    path(
        "create_credential.js",
        CreateCredentialJS.as_view(content_type="text/javascript"),
        name="create_credential",
    ),
    path(
        "get_credential.js",
        GetCredentialJS.as_view(content_type="text/javascript"),
        name="get_credential",
    ),
]
