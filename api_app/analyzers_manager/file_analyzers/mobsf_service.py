import logging
import time

import requests

from api_app.analyzers_manager.classes import FileAnalyzer

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
    activity_duration: int = (
        60  # duration for mobsf to collect sufficient info in dynamic analysis before generating report
    )

    # API Endpoints
    UPLOAD_ENDPOINT = "/api/v1/upload"
    START_STATIC_ANALYSIS = "/api/v1/scan"
    GENERATE_STATIC_ANALYSIS_REPORT = "/api/v1/report_json"
    MOBSFY_ENDPOINT = "/api/v1/android/mobsfy"
    START_DYNAMIC_ANALYSIS = "/api/v1/dynamic/start_analysis"
    TLS_TESTS_ENDPOINT = "/api/v1/android/tls_tests"
    FRIDA_INSTRUMENT_ENDPOINT = "/api/v1/frida/instrument"
    GET_DEPENDENCIES_ENDPOINT = "/api/v1/frida/get_dependencies"
    STOP_DYNAMIC_ANALYSIS = "/api/v1/dynamic/stop_analysis"
    GENERATE_DYNAMIC_ANALYSIS_REPORT = "/api/v1/dynamic/report_json"

    def update(self) -> bool:
        pass

    def query_mobsf(self, endpoint, headers, data):
        response = requests.post(
            url=self.mobsf_host + endpoint,
            data=data,
            headers=headers,
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response

    def static_analysis(self, scan_hash, headers):
        data = {"hash": scan_hash}
        logger.info(f"Initiating static analysis with scan hash: {scan_hash}")
        scan_response = self.query_mobsf(self.START_STATIC_ANALYSIS, headers, data)
        scan_response.raise_for_status()
        logger.info(
            f"Static analysis for scan hash:{scan_hash} completed successfully, now generating JSON Report"
        )
        report_response = self.query_mobsf(self.GENERATE_STATIC_ANALYSIS_REPORT, headers, data)

        return report_response.json()

    def dynamic_analysis(self, scan_hash, headers):
        # job specific payload
        payload = {
            "general": {"hash": scan_hash},
            "mobsfy": {"identifier": self.identifier},
            "frida_instrumentation": {
                "hash": scan_hash,
                "default_hooks": self.default_hooks,
                "auxiliary_hooks": self.auxiliary_hooks,
                "frida_code": self.frida_code,
            },
        }

        logger.info(
            f"Configuring runtime environment with instance identifier: {self.identifier} for dynamic analysis with hash: {scan_hash}"
        )
        self.query_mobsf(self.MOBSFY_ENDPOINT, headers, payload["mobsfy"])

        logger.info(f"Initiating dynamic analysis for scan hash: {scan_hash}")
        self.query_mobsf(self.START_DYNAMIC_ANALYSIS, headers, payload["general"])

        logger.info(f"Starting tls tests for scan hash: {scan_hash}")
        self.query_mobsf(self.TLS_TESTS_ENDPOINT, headers, payload["general"])

        logger.info(
            f"Starting frida instrumentation with user provided hooks and code for scan with hash: {scan_hash}"
        )
        self.query_mobsf(self.FRIDA_INSTRUMENT_ENDPOINT, headers, payload["frida_instrumentation"])

        logger.info(f"Collecting runtime dependencies for scan hash: {scan_hash}")
        self.query_mobsf(self.GET_DEPENDENCIES_ENDPOINT, headers, payload["general"])

        logger.info(
            f"Waiting {self.activity_duration} seconds for dynamic analysis to collect sufficient information. Scan hash: {scan_hash}"
        )
        # pausing current run execution to provide enough time for mobsf to collect sufficient information before stopping
        time.sleep(self.activity_duration)

        logger.info(f"Stopping dynamic analysis for scan hash: {scan_hash} and generating JSON Report")
        self.query_mobsf(self.STOP_DYNAMIC_ANALYSIS, headers, payload["general"])

        dynamic_analysis_report = self.query_mobsf(
            self.GENERATE_DYNAMIC_ANALYSIS_REPORT, headers, payload["general"]
        )
        logger.info(f"JSON report for dynamic analysis with scan hash: {scan_hash} generated successfully")

        return dynamic_analysis_report.json()

    def run(self):
        headers = {"X-Mobsf-Api-Key": self._mobsf_api_key}
        binary = self.read_file_bytes()
        logger.info(f"File bytes for file:{self.filename} read successfully. Initiating upload request")

        upload_url = self.mobsf_host + self.UPLOAD_ENDPOINT
        upload_response = requests.post(
            url=upload_url,
            files={"file": (self.filename, binary, "application/octet-stream")},
            headers=headers,
            timeout=self.timeout,
        )
        upload_response.raise_for_status()
        scan_hash = upload_response.json()["hash"]
        logger.info(f"File {self.filename} uploaded successfully and the scan hash is: {scan_hash}")

        static_analysis_json = self.static_analysis(scan_hash, headers)
        dynamic_analysis_json = (
            self.dynamic_analysis(scan_hash, headers) if self.enable_dynamic_analysis else {}
        )
        results = {
            "static_analysis_results": static_analysis_json,
            "dynamic_analysis_results": dynamic_analysis_json,
        }

        return results
