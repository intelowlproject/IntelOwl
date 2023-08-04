# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from logging import getLogger

from django.apps import AppConfig
from django.db import ProgrammingError

logger = getLogger(__name__)


class ApiAppConfig(AppConfig):
    name = "api_app"

    @staticmethod
    def ready():
        # flake8: noqa
        from django.core.cache import cache

        from authentication.views import DurinAuthenticationScheme  # noqa

        from . import signals  # noqa

        logger.info("Cleaning cache")
        try:
            cache.clear()
        except ProgrammingError:
            logger.info("No table to clean")
