import logging

import requests

from api_app.analyzers_manager.classes import FileAnalyzer
from tests.mock_utils import MockUpResponse, if_mock_connections, patch

logger = logging.getLogger(__name__)


class MobSF_Service(FileAnalyzer):
    mobsf_host: str
    identifier: str
    timeout: int = 30
    enable_dynamic_analysis: bool = False
    _mobsf_api_key: str
    default_hooks: str = "root_bypass"
    auxiliary_hooks: str = ""
    frida_code: str = ""

    def update(self) -> bool:
        pass

    def static_analysis(self, scan_hash, headers):
        logger.info(f"Initiating static analysis with scan hash: {scan_hash}")
        scan_url = self.mobsf_host + "/api/v1/scan"
        data = {"hash": scan_hash}
        scan_response = requests.post(
            url=scan_url, data=data, headers=headers, timeout=self.timeout
        )
        scan_response.raise_for_status()
        logger.info(
            f"Static analysis for scan hash:{scan_hash} completed successfully, now generating JSON Report"
        )

        report_url = self.mobsf_host + "/api/v1/report_json"
        report_response = requests.post(
            url=report_url, data=data, headers=headers, timeout=self.timeout
        )
        report_response.raise_for_status()
        return report_response.json()

    def dynamic_analysis(self, scan_hash, headers):
        logger.info(
            f"Configuring runtime environment with android instance identifier: {self.identifier}"
        )
        mobsfy_runtime_response = requests.post(
            url=self.mobsf_host + "/api/v1/android/mobsfy",
            headers=headers,
            data={"identifier": self.identifier},
            timeout=self.timeout,
        )
        mobsfy_runtime_response.raise_for_status()

        logger.info(f"Initiating dynamic analysis for scan hash: {scan_hash}")
        start_dynamic_analysis_response = requests.post(
            url=self.mobsf_host + "/api/v1/dynamic/start_analysis",
            headers=headers,
            data={"hash": scan_hash},
            timeout=self.timeout,
        )
        start_dynamic_analysis_response.raise_for_status()
        logger.info(f"Dynamic analyzer started successfully for scan hash: {scan_hash}")

        logger.info(f"Running tls tests for scan with hash: {scan_hash}")
        tls_tests_response = requests.post(
            url=self.mobsf_host + "/api/v1/android/tls_tests",
            headers=headers,
            data={"hash": scan_hash},
            timeout=self.timeout,
        )
        tls_tests_response.raise_for_status()

        logger.info(
            f"Starting frida instrumentation with user provided hooks and code for scan with hash: {scan_hash}"
        )
        start_frida_instrumentation_response = requests.post(
            url=self.mobsf_host + "/api/v1/frida/instrument",
            headers=headers,
            data={
                "hash": scan_hash,
                "default_hooks": self.default_hooks,
                "auxiliary_hooks": self.auxiliary_hooks,
                "frida_code": self.frida_code,
            },
            timeout=self.timeout,
        )
        start_frida_instrumentation_response.raise_for_status()
        logger.info(
            f"Frida instrumentation started successfully for scan with hash: {scan_hash}. Initiating collection of runtime dependencies"
        )

        get_runtime_dependency_response = requests.post(
            url=self.mobsf_host + "/api/v1/frida/get_dependencies",
            headers=headers,
            data={"hash": scan_hash},
            timeout=self.timeout,
        )
        get_runtime_dependency_response.raise_for_status()
        logger.info(
            f"Successfully collected runtime dependencies for scan hash: {scan_hash}"
        )

        logger.info(
            f"Stopping dyanmic analyzer and generating JSON report for scan hash: {scan_hash}"
        )
        stop_dynamic_analysis = requests.post(
            url=self.mobsf_host + "/api/v1/dynamic/stop_analysis",
            headers=headers,
            data={"hash": scan_hash},
            timeout=self.timeout,
        )
        stop_dynamic_analysis.raise_for_status()

        dynamic_analysis_report = requests.post(
            url=self.mobsf_host + "/api/v1/dynamic/report_json",
            headers=headers,
            data={"hash": scan_hash},
            timeout=self.timeout,
        )
        dynamic_analysis_report.raise_for_status()
        logger.info(
            f"JSON report for dynamic analysis with scan hash: {scan_hash} generated successfully"
        )

        return dynamic_analysis_report.json()

    def run(self):
        headers = {"X-Mobsf-Api-Key": self._mobsf_api_key}
        binary = self.read_file_bytes()
        logger.info(
            f"File bytes for file:{self.filename} read successfully. Initiating upload request"
        )

        upload_url = self.mobsf_host + "/api/v1/upload"
        upload_response = requests.post(
            url=upload_url,
            files={"file": (self.filename, binary, "application/octet-stream")},
            headers=headers,
            timeout=self.timeout,
        )
        upload_response.raise_for_status()
        scan_hash = upload_response.json()["hash"]
        logger.info(
            f"File upload for file: {self.filename} is successful and the scan hash is: {scan_hash}"
        )

        static_analysis_json = self.static_analysis(scan_hash, headers)
        dynamic_analysis_json = (
            self.dynamic_analysis(scan_hash, headers)
            if self.enable_dynamic_analysis
            else {}
        )
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
