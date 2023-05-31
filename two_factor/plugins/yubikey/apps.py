from django.apps import AppConfig, apps
from django.core.exceptions import ImproperlyConfigured

from two_factor.plugins.registry import registry


class TwoFactorYubikeyConfig(AppConfig):
    name = "two_factor.plugins.yubikey"
    verbose_name = "Django Two Factor Authentication – Yubikey Method"

    def ready(self):
        if not apps.is_installed("otp_yubikey"):
            raise ImproperlyConfigured(
                "'otp_yubikey' must be installed to be able to use the yubikey plugin."
            )

        from .method import YubikeyMethod

        registry.register(YubikeyMethod())
