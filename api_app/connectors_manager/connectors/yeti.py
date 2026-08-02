# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging

import requests
from django.conf import settings

from api_app.connectors_manager.classes import CTIConnector
from api_app.connectors_manager.exceptions import ConnectorRunException

logger = logging.getLogger(__name__)


class YETI(CTIConnector):
    verify_ssl: bool
    _url_key_name: str
    _api_key_name: str

    def health_check(self, user=None) -> tuple:
        params = self._config.parameters.annotate_configured(self._config, user).annotate_value_for_user(
            self._config, user
        )
        url = None
        api_key = None

        for param in params:
            if param.name == "url_key_name":
                url = param.value
            elif param.name == "api_key_name":
                api_key = param.value

        if not url:
            logger.info("Healthcheck failed: Missing config url")
            return False, "Missing config url"
        if not api_key:
            logger.info("Healthcheck failed: Missing config api key")
            return False, "Missing config api key"

        if settings.STAGE_CI or settings.MOCK_CONNECTIONS:
            return True, "Mock connection successful"

        base_url = url.rstrip("/")
        auth_url = f"{base_url}/api/v2/auth/api-token"

        auth_headers = {"x-yeti-apikey": api_key, "User-Agent": "IntelOwl"}

        try:
            verify_ssl = getattr(self, "verify_ssl", False)

            # Posting the API key to YETI's authentication endpoint returns an
            # access token on success (YETI API v2). A valid access token confirms
            # that the API key is valid and the YETI instance is reachable.
            # Ref: https://yeti-platform.io/docs/api/#authentication
            auth_resp = requests.post(
                url=auth_url,
                headers=auth_headers,
                verify=verify_ssl,
                timeout=10,
            )
            auth_resp.raise_for_status()
            access_token = auth_resp.json().get("access_token")

            if access_token:
                return True, "Connected successfully"
            else:
                logger.info(f"Healthcheck failed for {self}: No access token in response.")
                return False, "No access token in response"

        except requests.RequestException as e:
            logger.info(f"Healthcheck failed: YETI Auth Request failed for {self}. Error: {e}")
            return False, f"Auth Request failed: {e}"
        except Exception as e:
            logger.exception(f"Unexpected error in YETI health_check: {e}")
            return False, f"Unexpected error: {e}"

    def _get_yeti_observable_type(self) -> str:
        """
        Convert IntelOwl classification to YETI's expected observable type.
        """
        obs_classification = self.classification

        if obs_classification == "ip":
            ip_ver = self.ip_version
            if ip_ver == 4:
                return "ipv4"
            elif ip_ver == 6:
                return "ipv6"
            else:
                return "generic"
        elif obs_classification == "domain":
            return "hostname"
        elif obs_classification == "hash":
            return "generic"
        else:
            return obs_classification

    def run(self):
        obs_value = self.observable_value
        obs_type = self._get_yeti_observable_type()

        # create context
        context = {
            "source": "IntelOwl",
            "report": self.analysis_url,
            "status": "analyzed",
            "date": str(self._job.received_request_time),
            "description": f"IntelOwl's analysis report for Job: {self.job_id} | {obs_value} | {obs_type}",
            "analyzers executed": ", ".join(self.analyzer_names),
        }

        # Add enrichment data to context when available
        if self.has_data_model:
            enrichment = self.get_enrichment_summary()
            for key, value in enrichment.items():
                context[key] = str(value) if not isinstance(value, str) else value

        # get job tags
        tags = self.tag_labels

        # request payload
        payload = {
            "tags": tags,
            "observable": {
                "type": obs_type,
                "value": obs_value,
                "context": [context],
            },
        }

        if self._url_key_name and self._url_key_name.endswith("/"):
            self._url_key_name = self._url_key_name[:-1]

        # auth
        auth_url = f"{self._url_key_name}/api/v2/auth/api-token"
        auth_headers = {"x-yeti-apikey": self._api_key_name, "User-Agent": "IntelOwl"}

        try:
            auth_resp = requests.post(
                url=auth_url,
                headers=auth_headers,
                verify=self.verify_ssl,
                timeout=60,
            )
            auth_resp.raise_for_status()
            access_token = auth_resp.json().get("access_token")

            if not access_token:
                raise ConnectorRunException("Failed to obtain access token from YETI.")
        except requests.RequestException as e:
            raise ConnectorRunException(f"YETI Auth Request failed: {e}")

        # create observable with `obs_value` if it doesn't exists
        # new context, tags, source are appended with existing ones

        url = f"{self._url_key_name}/api/v2/observables/extended"
        headers = {
            "Accept": "application/json",
            "User-Agent": "IntelOwl",
            "Authorization": f"Bearer {access_token}",
        }

        try:
            resp = requests.post(
                url=url,
                headers=headers,
                json=payload,
                verify=self.verify_ssl,
                timeout=60,
            )
            resp.raise_for_status()
        except requests.RequestException as e:
            raise ConnectorRunException(e)

        return resp.json()
