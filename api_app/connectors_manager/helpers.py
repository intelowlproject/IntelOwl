# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.conf import settings

import os
import json


def get_connector_config():
    config_path = os.path.join(
        settings.BASE_DIR, "configuration", "connector_config.json"
    )
    with open(config_path) as f:
        connectors_config = json.load(f)
    return connectors_config
