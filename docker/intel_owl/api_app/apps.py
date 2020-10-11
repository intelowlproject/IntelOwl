from django.apps import AppConfig


class ApiAppConfig(AppConfig):
    name = "api_app"

    def ready(self):
        # flake8: noqa
        import api_app.signal_handlers as signals
