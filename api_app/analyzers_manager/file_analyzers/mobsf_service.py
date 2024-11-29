import logging

import requests

from api_app.analyzers_manager.classes import FileAnalyzer
from tests.mock_utils import MockUpResponse, if_mock_connections, patch

logger = logging.getLogger(__name__)


class MobSF_Service(FileAnalyzer):
    mobsf_host: str
    _mobsf_api_key: str

    def static_analysis(self, scan_hash, headers):

        scan_url = self.mobsf_host + "/api/v1/scan"
        data = {"hash": scan_hash}
        scan_response = requests.post(url=scan_url, data=data, headers=headers)
        scan_response.raise_for_status()

        report_url = self.mobsf_host + "/api/v1/report_json"
        report_response = requests.post(url=report_url, data=data, headers=headers)
        report_response.raise_for_status()
        return report_response.json()

    def dynamic_analysis(self, scan_hash, headers):

        mobsfy_runtime_response = requests.post(
            url=self.mobsf_host + "/api/v1/android/mobsfy",
            headers=headers,
            data={"identifier": "127.0.0.1:6555"},
        )
        mobsfy_runtime_response.raise_for_status()

        start_dynamic_analysis_response = requests.post(
            url=self.mobsf_host + "/api/v1/dynamic/start_analysis",
            headers=headers,
            data={"hash": scan_hash},
        )
        start_dynamic_analysis_response.raise_for_status()

        tls_tests_response = requests.post(
            url=self.mobsf_host + "/api/v1/android/tls_tests",
            headers=headers,
            data={"hash": scan_hash},
        )
        tls_tests_response.raise_for_status()

        start_frida_instrumentation_response = requests.post(
            url=self.mobsf_host + "/api/v1/frida/instrument",
            headers=headers,
            data={
                "hash": scan_hash,
                "default_hooks": "api_monitor,ssl_pinning_bypass,root_bypass,debugger_check_bypass",
                "auxiliary_hooks": "",
                "frida_code": "",
            },
        )
        start_frida_instrumentation_response.raise_for_status()

        get_runtime_dependency_response = requests.post(
            url=self.mobsf_host + "/api/v1/frida/get_dependencies",
            headers=headers,
            data={"hash": scan_hash},
        )
        get_runtime_dependency_response.raise_for_status()

        stop_dynamic_analysis = requests.post(
            url=self.mobsf_host + "/api/v1/dynamic/stop_analysis",
            headers=headers,
            data={"hash": scan_hash},
        )
        stop_dynamic_analysis.raise_for_status()

        dynamic_analysis_report = requests.post(
            url=self.mobsf_host + "/api/v1/dynamic/report_json",
            headers=headers,
            data={"hash": scan_hash},
        )
        dynamic_analysis_report.raise_for_status()

        return dynamic_analysis_report.json()

    def run(self):
        headers = {"X-Mobsf-Api-Key": self._mobsf_api_key}
        binary = self.read_file_bytes()

        upload_url = self.mobsf_host + "/api/v1/upload"
        upload_response = requests.post(
            url=upload_url,
            files={"file": (self.filename, binary, "application/octet-stream")},
            headers=headers,
        )
        upload_response.raise_for_status()
        scan_hash = upload_response.json()["hash"]

        static_analysis_json = self.static_analysis(scan_hash, headers)
        dynamic_analysis_json = self.dynamic_analysis(scan_hash, headers)

        results = {
            "static_analysis_results": static_analysis_json,
            "dynamic_analysis_results": dynamic_analysis_json,
        }

        return results

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.post",
                    return_value=MockUpResponse(
                        {
                            "file_name": "diva-beta.apk",
                            "hash": "82ab8b2193b3cfb1c737e3a786be363a",
                            "scan_type": "apk",
                        },
                        200,
                    ),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
