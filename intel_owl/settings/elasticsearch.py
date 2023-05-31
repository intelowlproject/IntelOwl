# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

# Elastic Search Configuration
from intel_owl import secrets

if secrets.get_secret("ELASTICSEARCH_ENABLED", False) == "True":
    ELASTICSEARCH_DSL = {
        "default": {"hosts": secrets.get_secret("ELASTICSEARCH_HOST")},
    }
    ELASTICSEARCH_DSL_INDEX_SETTINGS = {
        "number_of_shards": int(secrets.get_secret("ELASTICSEARCH_NO_OF_SHARDS")),
        "number_of_replicas": int(secrets.get_secret("ELASTICSEARCH_NO_OF_REPLICAS")),
    }
else:
    ELASTICSEARCH_DSL_AUTOSYNC = False
    ELASTICSEARCH_DSL = {
        "default": {"hosts": ""},
    }
