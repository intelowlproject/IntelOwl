# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.core.cache import cache
from cache_memoize import cache_memoize

from .serializers import ConnectorConfigSerializer


@cache_memoize(100)
def get_verified_connector_config():
    success, config = ConnectorConfigSerializer.read_and_verify_config()
    if success:
        cache.set("verified_connectors_config", config)
    return config
