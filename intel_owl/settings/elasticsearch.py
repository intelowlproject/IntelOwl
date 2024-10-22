# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from elasticsearch import Elasticsearch

from intel_owl import secrets

ELASTICSEARCH_BI_ENABLED = (
    secrets.get_secret("ELASTICSEARCH_BI_ENABLED", False) == "True"
)
if ELASTICSEARCH_BI_ENABLED:
    ELASTICSEARCH_BI_HOST = secrets.get_secret("ELASTICSEARCH_BI_HOST").split(",")
    ELASTICSEARCH_BI_INDEX = secrets.get_secret("ELASTICSEARCH_BI_INDEX")

    if not ELASTICSEARCH_BI_HOST or not ELASTICSEARCH_BI_INDEX:
        print("Elasticsearch not correctly configured")

    else:
        ELASTICSEARCH_BI_CLIENT = Elasticsearch(
            ELASTICSEARCH_BI_HOST,
            maxsize=20,
            max_retries=10,
            retry_on_timeout=True,
            timeout=30,
        )
        if not ELASTICSEARCH_BI_CLIENT.ping():
            print(
                f"ELASTICSEARCH BI client configuration did not connect correctly: {ELASTICSEARCH_BI_CLIENT.info()}"
            )

ELASTIC_HOST = secrets.get_secret("ELASTIC_HOST")
if ELASTIC_HOST:
    elastic_client_settings = {"hosts": ELASTIC_HOST}

    ELASTIC_PASSWORD = secrets.get_secret("ELASTIC_PASSWORD")
    if ELASTIC_PASSWORD:
        elastic_client_settings["basic_auth"] = ("elastic", ELASTIC_PASSWORD)
    ELASTICSEARCH_DSL = {"default": elastic_client_settings}

    ELASTICSEARCH_DSL_INDEX_SETTINGS = {
        "number_of_shards": int(secrets.get_secret("ELASTICSEARCH_DSL_NO_OF_SHARDS")),
        "number_of_replicas": int(
            secrets.get_secret("ELASTICSEARCH_DSL_NO_OF_REPLICAS")
        ),
    }
else:
    ELASTICSEARCH_DSL_AUTOSYNC = False
    ELASTICSEARCH_DSL = {
        "default": {"hosts": ""},
    }
