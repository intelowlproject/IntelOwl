# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.apps import AppConfig
from logging import getLogger

logger = getLogger(__name__)


class ApiAppConfig(AppConfig):
    name = "api_app"

    def ready(self):
        # flake8: noqa
        import api_app.signals
        from authentication.views import DurinAuthenticationScheme
        from django.core.cache import cache

        logger.info("Cleaning cache")
        cache.clear()
