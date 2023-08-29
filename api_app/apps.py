# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import uuid
from logging import getLogger

from django.apps import AppConfig
from django.db import ProgrammingError

logger = getLogger(__name__)


class ApiAppConfig(AppConfig):
    name = "api_app"
    cache_cleared = False

    def ready(self):
        # flake8: noqa
        from django.core.cache import cache

        from authentication.views import DurinAuthenticationScheme  # noqa

        from . import signals  # noqa

        if not self.cache_cleared:
            logger.info("Cleaning cache")
            ApiAppConfig.cache_cleared = True
            try:
                cache.clear()
            except ProgrammingError:
                logger.info("No table to clean")
            finally:

                from certego_saas.models import User
                from intel_owl.celery import DEFAULT_QUEUE
                from intel_owl.tasks import create_caches

                for user in User.objects.exclude(email=""):
                    create_caches.apply_async(
                        routing_key=DEFAULT_QUEUE,
                        MessageGroupId=str(uuid.uuid4()),
                        args=[user.pk],
                    )
