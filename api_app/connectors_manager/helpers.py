# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.conf import settings
from django.core.cache import cache

import os
import json
import logging

from api_app.connectors_manager.serializers import ConnectorConfigSerializer


logger = logging.getLogger(__name__)


def get_verified_connector_config():
    # get cached json else cache and return
    config = cache.get("verified_connectors_config", None)
    if config is not None:
        return config
    else:
        success, config = verify_connector_config()
        if success:
            cache.set("verified_connectors_config", config)
        return config


def verify_connector_config():
    config_path = os.path.join(
        settings.BASE_DIR, "configuration", "connector_config.json"
    )
    with open(config_path) as f:
        connector_config = json.load(f)
        serializer_errors = {}
        for key, config in connector_config.items():
            serializer = ConnectorConfigSerializer(data=config)
            if serializer.is_valid():
                connector_config[key] = serializer.data  # mutate with processed config
            else:
                serializer_errors[key] = serializer.errors

        if bool(serializer_errors):  # returns False if empty
            logger.error(f"connector config serializer failed: {serializer_errors}")
            return False, {}
        return True, connector_config
