# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import ipaddress

import requests
from django.conf import settings

from api_app.connectors_manager import classes
from api_app.connectors_manager.exceptions import ConnectorRunException


class YETI(classes.Connector):
    verify_ssl: bool
    _url_key_name: str
    _api_key_name: str

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
