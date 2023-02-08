# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from logging import getLogger

from django.apps import AppConfig

logger = getLogger(__name__)


class ApiAppConfig(AppConfig):
    name = "api_app"

    def ready(self):
        # flake8: noqa
        from django.core.cache import cache

        import api_app.signals
        from authentication.views import DurinAuthenticationScheme

        logger.info("Cleaning cache")
        cache.clear()
