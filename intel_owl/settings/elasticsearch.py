# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

# Elastic Search Configuration
from ssl import create_default_context

from elasticsearch import Elasticsearch

from intel_owl import secrets
from intel_owl.settings import CONFIG_ROOT

ELASTICSEARCH_BI_ENABLED = (
    secrets.get_secret("ELASTICSEARCH_BI_ENABLED", False) == "True"
)
if ELASTICSEARCH_BI_ENABLED:
    ELASTICSEARCH_BI_HOST = secrets.get_secret("ELASTICSEARCH_BI_HOST").split(",")
    ELASTICSEARCH_SSL_CERTIFICATE_PATH = CONFIG_ROOT / secrets.get_secret(
        "ELASTICSEARCH_SSL_CERTIFICATE_FILE_NAME", "elasticsearch.crt"
    )
    ELASTICSEARCH_BI_INDEX = secrets.get_secret("ELASTICSEARCH_BI_INDEX")
    if (
        not ELASTICSEARCH_BI_HOST
        or not ELASTICSEARCH_SSL_CERTIFICATE_PATH
        or not ELASTICSEARCH_BI_INDEX
    ):
        print("Elasticsearch not correctly configured")
    else:
        elastic_ssl_context = create_default_context(
            cafile=str(ELASTICSEARCH_SSL_CERTIFICATE_PATH)
        )
        from importlib.metadata import version

        v = version("elasticsearch")
        major_version = int(v.split(".")[0])
        if major_version < 8:
            ELASTICSEARCH_CLIENT = Elasticsearch(
                ELASTICSEARCH_BI_HOST,
                ssl_context=elastic_ssl_context,
                scheme="https",
                maxsize=20,
                max_retries=10,
                retry_on_timeout=True,
                timeout=30,
                sniff_on_connection_fail=True,
                sniff_timeout=30,
            )
        else:
            raise RuntimeError(f"Elastic version {v} is not supported at the moment.")

ELASTICSEARCH_DSL_ENABLED = (
    secrets.get_secret("ELASTICSEARCH_DSL_ENABLED", False) == "True"
)
if ELASTICSEARCH_DSL_ENABLED:
    ELASTICSEARCH_DSL_HOST = secrets.get_secret("ELASTICSEARCH_DSL_HOST")

    ELASTICSEARCH_DSL = {
        "default": {"hosts": ELASTICSEARCH_DSL_HOST},
    }
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
