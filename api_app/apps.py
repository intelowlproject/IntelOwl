# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
from logging import getLogger

from django.apps import AppConfig

logger = getLogger(__name__)


class ApiAppConfig(AppConfig):
    name = "api_app"
