# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from elasticsearch import Elasticsearch

from intel_owl import secrets

# business intelligence (bi)
ELASTICSEARCH_BI_ENABLED = (
    secrets.get_secret("ELASTICSEARCH_BI_ENABLED", False) == "True"
)
if ELASTICSEARCH_BI_ENABLED:
    ELASTICSEARCH_BI_HOST = secrets.get_secret("ELASTICSEARCH_BI_HOST").split(",")
    ELASTICSEARCH_BI_INDEX = secrets.get_secret("ELASTICSEARCH_BI_INDEX")
    if ELASTICSEARCH_BI_HOST and ELASTICSEARCH_BI_INDEX:
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
    else:
        print("Elasticsearch not correctly configured")


# advanced search
ELASTICSEARCH_DSL_ENABLED = (
    secrets.get_secret("ELASTICSEARCH_DSL_ENABLED", False) == "True"
)
if ELASTICSEARCH_DSL_ENABLED:
    ELASTICSEARCH_DSL_HOST = secrets.get_secret("ELASTICSEARCH_DSL_HOST")
    if ELASTICSEARCH_DSL_HOST:
        elastic_search_conf = {"hosts": ELASTICSEARCH_DSL_HOST}

        ELASTICSEARCH_DSL_PASSWORD = secrets.get_secret("ELASTICSEARCH_DSL_PASSWORD")
        if ELASTICSEARCH_DSL_PASSWORD:
            elastic_search_conf["basic_auth"] = (
                "elastic",
                ELASTICSEARCH_DSL_PASSWORD,
            )
        if "elasticsearch:9200" in ELASTICSEARCH_DSL_HOST:
            # in case we use Elastic as container we need the generated
            # in case we use Elastic as external service it should have a valid cert
            elastic_search_conf["verify_certs"] = (
                "/opt/deploy/intel_owl/certs/elastic_instance/elasticsearch.crt"
            )
            elastic_search_conf["ca_certs"] = (
                "/opt/deploy/intel_owl/certs/elastic_ca/ca.crt"
            )
        ELASTICSEARCH_DSL_CLIENT = Elasticsearch(**elastic_search_conf)
        if not ELASTICSEARCH_DSL_CLIENT.ping():
            print(
                f"ELASTICSEARCH DSL client configuration did not connect correctly: {ELASTICSEARCH_DSL_CLIENT.info()}"
            )
    else:
        print(
            "you have to configure ELASTIC_HOST with the URL of your ElasticSearch instance"
        )
