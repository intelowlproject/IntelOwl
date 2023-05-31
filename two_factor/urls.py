from django.apps.registry import apps
from django.urls import include, path

from two_factor.views import (
    BackupTokensView,
    DisableView,
    LoginView,
    ProfileView,
    QRGeneratorView,
    SetupCompleteView,
    SetupView,
)

core = [
    path(
        "account/login/",
        LoginView.as_view(),
        name="login",
    ),
    path(
        "account/two_factor/setup/",
        SetupView.as_view(),
        name="setup",
    ),
    path(
        "account/two_factor/qrcode/",
        QRGeneratorView.as_view(),
        name="qr",
    ),
    path(
        "account/two_factor/setup/complete/",
        SetupCompleteView.as_view(),
        name="setup_complete",
    ),
    path(
        "account/two_factor/backup/tokens/",
        BackupTokensView.as_view(),
        name="backup_tokens",
    ),
]

profile = [
    path(
        "account/two_factor/",
        ProfileView,
        name="profile",
    ),
    path(
        "account/two_factor/disable/",
        DisableView,
        name="disable",
    ),
]

plugin_urlpatterns = []
for app_config in apps.get_app_configs():
    if app_config.name.startswith("two_factor.plugins."):
        # Phonenumber used to be include in the two_factor core. Because we
        # don't want to change the url names and break backwards compatibility
        # we keep the urls of the phonenumber plugin in the core two_factor
        # namespace.
        if app_config.name == "two_factor.plugins.phonenumber":
            namespace = None
        else:
            namespace = app_config.label
        try:
            plugin_urlpatterns.append(
                path(
                    f"account/two_factor/{app_config.url_prefix}/",
                    include(f"{app_config.name}.urls", namespace),
                ),
            )
        except AttributeError:
            pass

urlpatterns = (core + profile + plugin_urlpatterns, "two_factor")
