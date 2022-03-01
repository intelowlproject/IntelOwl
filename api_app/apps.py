# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.apps import AppConfig


class ApiAppConfig(AppConfig):
    name = "api_app"

    def ready(self):
        # flake8: noqa
        from api_app.auth.views import DurinAuthenticationScheme
