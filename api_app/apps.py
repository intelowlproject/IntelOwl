# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
from logging import getLogger

from django.apps import AppConfig

logger = getLogger(__name__)


class ApiAppConfig(AppConfig):
    name = "api_app"

    def ready(self):  # skipcq: PYL-R0201
        from api_app.helpers import patch_requests_default_timeout

        patch_requests_default_timeout()
        from . import signals  # noqa
