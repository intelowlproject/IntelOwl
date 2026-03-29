# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests
from django.conf import settings

from api_app.connectors_manager import classes
from api_app.connectors_manager.exceptions import ConnectorRunException
from tests.mock_utils import MockUpResponse, if_mock_connections, patch


class YETI(classes.Connector):
    verify_ssl: bool
    _url_key_name: str
    _api_key_name: str

    # health_check test taken from https://yeti-platform.io/docs/api/
    def health_check(self, user=None):
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
            # no ssl cert validation in yeti found in docs

        if not url:
            raise RuntimeError("Missing config url")
        if not api_key:
            raise RuntimeError("Missing config api key")
        token_resp = requests.post(
            url=f"{url}/api/v2/auth/api-token",
            headers={"x-yeti-apikey": api_key},
            timeout=10,
        )
        token_resp.raise_for_status()
        access_token = token_resp.json().get("access_token")
        if not access_token:
            raise RuntimeError("No access token from Yeti.")

        resp = requests.get(
            url=f"{url}/api/v2/auth/me",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=10,
        )
        resp.raise_for_status()
        return True

    def run(self):
        # get observable value and type
        if self._job.is_sample:
            obs_value = self._job.analyzable.md5
            obs_type = "file"
        else:
            obs_value = self._job.analyzable.name
            obs_type = self._job.analyzable.classification

        # create context
        context = {
            "source": "IntelOwl",
            "report": f"{settings.WEB_CLIENT_URL}/jobs/{self.job_id}",
            "status": "analyzed",
            "date": str(self._job.finished_analysis_time),
            "description": f"IntelOwl's analysis report for Job: {self.job_id} | {obs_value} | {obs_type}",
            "analyzers executed": ", ".join(
                list(self._job.analyzers_to_execute.all().values_list("name", flat=True))
            ),
        }

        # get job tags
        tags = list(self._job.tags.all().values_list("label", flat=True))

        # request payload
        payload = {
            "value": obs_value,
            "source": "IntelOwl",
            "tags": tags,
            "context": context,
        }
        headers = {"Accept": "application/json", "X-Api-Key": self._api_key_name}
        if self._url_key_name and self._url_key_name.endswith("/"):
            self._url_key_name = self._url_key_name[:-1]
        url = f"{self._url_key_name}/api/v2/observables/"

        # create observable with `obs_value` if it doesn't exists
        # new context, tags, source are appended with existing ones
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

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.post",
                    return_value=MockUpResponse({"access_token": "test_token"}, 200),
                )
            ),
            if_mock_connections(
                patch(
                    "requests.get",
                    return_value=MockUpResponse({"username": "admin"}, 200),
                )
            ),
        ]
        return super()._monkeypatch(patches=patches)
