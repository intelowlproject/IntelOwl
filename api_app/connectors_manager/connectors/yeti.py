# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import ipaddress
import logging

import requests
from django.conf import settings

from api_app.connectors_manager import classes
from api_app.connectors_manager.exceptions import ConnectorRunException

logger = logging.getLogger(__name__)


class YETI(classes.Connector):
    verify_ssl: bool
    _url_key_name: str
    _api_key_name: str

    def health_check(self, user=None) -> bool:
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
            return False
        if not api_key:
            logger.info("Healthcheck failed: Missing config api key")
            return False

        if settings.STAGE_CI or settings.MOCK_CONNECTIONS:
            return True

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
                return True
            else:
                logger.info(f"Healthcheck failed for {self}: No access token in response.")
                return False

        except requests.RequestException as e:
            logger.info(f"Healthcheck failed: YETI Auth Request failed for {self}. Error: {e}")
            return False
        except Exception as e:
            logger.exception(f"Unexpected error in YETI health_check: {e}")
            return False

    def run(self):
        # get observable value and type
        if self._job.is_sample:
            obs_value = self._job.analyzable.md5
            obs_type = "file"
        else:
            obs_value = self._job.analyzable.name
            obs_type = self._job.analyzable.classification

        # convert obs_type to YETI's expected types if possible
        if obs_type == "ip":
            # mark whether the IP is ipv4 or ipv6, fallback to generic on error
            try:
                ip_obj = ipaddress.ip_address(obs_value)
                if ip_obj.version == 4:
                    obs_type = "ipv4"
                elif ip_obj.version == 6:
                    obs_type = "ipv6"
                else:
                    obs_type = "generic"
            except Exception:
                obs_type = "generic"
        elif obs_type == "domain":
            obs_type = "hostname"
        elif obs_type == "hash":
            obs_type = "generic"

        # create context
        context = {
            "source": "IntelOwl",
            "report": f"{settings.WEB_CLIENT_URL}/jobs/{self.job_id}",
            "status": "analyzed",
            "date": str(self._job.received_request_time),
            "description": f"IntelOwl's analysis report for Job: {self.job_id} | {obs_value} | {obs_type}",
            "analyzers executed": ", ".join(
                list(self._job.analyzers_to_execute.all().values_list("name", flat=True))
            ),
        }

        # get job tags
        tags = list(self._job.tags.all().values_list("label", flat=True))

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
