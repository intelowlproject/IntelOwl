from django.apps import AppConfig

from two_factor.plugins.registry import registry


class TwoFactorEmailConfig(AppConfig):
    name = "two_factor.plugins.email"
    verbose_name = "Django Two Factor Authentication – Email Method"

    def ready(self):
        from .method import EmailMethod

        registry.register(EmailMethod())
