# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
import re
import time

import requests

from api_app.analyzers_manager.classes import FileAnalyzer
from api_app.exceptions import AnalyzerConfigurationException, AnalyzerRunException
from tests.mock_utils import MockResponse, if_mock_connections, patch

logger = logging.getLogger(__name__)


class CuckooAnalysis(FileAnalyzer):
    def set_params(self, params):
        # cuckoo installation can be with or without the api_token
        # it depends on version and configuration
        self.session = requests.Session()
        api_key = self._secrets["api_key_name"]
        if not api_key:
            logger.info(
                f"{self.__repr__()}, (md5: {self.md5}) -> Continuing w/o API key.."
            )
        else:
            self.session.headers["Authorization"] = f"Bearer {api_key}"

        self.cuckoo_url = self._secrets["url_key_name"]
        self.task_id = 0
        self.result = {}
        # no. of tries requesting new scan
        self.max_post_tries = params.get("max_post_tries", 5)
        # no. of tries when polling for result
        self.max_get_tries = params.get("max_poll_tries", 20)

    def run(self):
        if not self.cuckoo_url:
            raise AnalyzerConfigurationException("cuckoo URL missing")
        binary = self.read_file_bytes()
        if not binary:
            raise AnalyzerRunException("is the binary empty?!")

        self.__cuckoo_request_scan(binary)
        self.__cuckoo_poll_result()
        result = self.__cuckoo_retrieve_and_create_report()

        return result

    def __cuckoo_request_scan(self, binary):
        logger.info(f"requesting scan for file: ({self.filename},{self.md5})")

        # send the file for analysis
        name_to_send = self.filename if self.filename else self.md5
        files = {"file": (name_to_send, binary)}
        post_success = False
        response = None
        for chance in range(self.max_post_tries):
            logger.info(
                f"request #{chance} for file analysis of ({self.filename},{self.md5})"
            )
            response = self.session.post(
                self.cuckoo_url + "tasks/create/file", files=files
            )
            if response.status_code != 200:
                logger.info(
                    "failed post to start cuckoo analysis, status code {}"
                    "".format(response.status_code)
                )
                time.sleep(5)
                continue
            post_success = True
            break

        if post_success:
            json_response = response.json()
            self.task_id = (
                json_response["task_ids"][0]
                if "task_ids" in json_response.keys()
                else json_response.get("task_id", 1)
            )
        else:
            raise AnalyzerRunException(
                "failed max tries to post file to cuckoo for analysis"
            )

    def __cuckoo_poll_result(self):
        logger.info(
            f"polling result for ({self.filename},{self.md5}), task_id: #{self.task_id}"
        )

        # poll for the result
        poll_time = 15
        get_success = False
        for chance in range(self.max_get_tries):
            logger.info(
                f"polling request #{chance + 1} for file ({self.filename},{self.md5})"
            )
            url = self.cuckoo_url + "tasks/view/" + str(self.task_id)
            response = self.session.get(url)
            json_response = response.json()
            status = json_response.get("task", {}).get("status", None)
            if status == "reported":
                get_success = True
                break
            elif status == "failed_processing":
                raise AnalyzerRunException(
                    "sandbox analysis failed."
                    f"cuckoo id: #{self.task_id}, status: 'failed_processing'"
                )
            else:
                time.sleep(poll_time)

        if not get_success:
            raise AnalyzerRunException(
                f"sandbox analysis timed out. cuckoo id: #{self.task_id}"
            )

    def __cuckoo_retrieve_and_create_report(self):
        logger.info(
            f"generating report for ({self.filename},{self.md5}), "
            f"task_id #{self.task_id}"
        )
        # download the report
        response = self.session.get(
            self.cuckoo_url + "tasks/report/" + str(self.task_id) + "/json"
        )
        json_response = response.json()

        # extract most IOCs as possible from signatures data reports
        signatures = json_response.get("signatures", [])
        list_description_signatures = []
        list_detailed_signatures = []
        list_potentially_malicious_urls_marks = []
        list_dyndns_domains_marks = []
        list_potentially_malicious_urls = []
        # flake8: noqa: E501
        regex_url = re.compile(
            r"((?:(?:ht|f)tp(?:s?)\:\/\/)(?:[!#$&-;=?-\[\]_a-z~]|%[0-9a-f]{2})+)(?![\)])",
            re.I,
        )
        for sig in signatures:
            sig_description = sig.get("description", "")
            sig_name = sig.get("name", "")
            sig_severity = sig.get("severity", "")
            sig_marks = sig.get("marks", [])
            list_description_signatures.append(sig_description)
            detailed_signature_data = {
                "description": sig_description,
                "name": sig_name,
                "severity": sig_severity,
                "marks": sig_marks,
            }
            list_detailed_signatures.append(detailed_signature_data)
            # get URL marks from some specific signatures
            if (
                "malicious URL found" in sig_description
                or "External resource URLs" in sig_description
                or "Powershell script" in sig_description
            ):
                list_potentially_malicious_urls_marks.extend(sig_marks)
            # get dydns domains from the specific signature
            if "networkdyndns_checkip" in sig_name:
                list_dyndns_domains_marks.extend(sig_marks)
            # look for IOCs extracted from specific signatures
            if "suspicious_process" in sig_name:
                for suspicious_process_mark in sig_marks:
                    suspicious_process_ioc = suspicious_process_mark.get("ioc", "")
                    match_url = re.search(regex_url, suspicious_process_ioc)
                    if match_url:
                        list_potentially_malicious_urls.append(match_url.group(1))

        # extract dyndns domains from specific signature, could be IOCs
        dyndns_domains = []
        for mark in list_dyndns_domains_marks:
            dydns_ioc = mark.get("ioc", "")
            dyndns_domains.append(dydns_ioc)

        # parse specific signatures
        for mark in list_potentially_malicious_urls_marks:
            ioc = mark.get("ioc", "")
            if ioc and ioc.startswith("http"):
                list_potentially_malicious_urls.append(ioc)
            if mark.get("config", {}):
                if mark["config"].get("url", []):
                    list_potentially_malicious_urls.extend(mark["config"]["url"])

        # remove duplicates
        list_potentially_malicious_urls = list(set(list_potentially_malicious_urls))

        # get suricata alerts if available
        suricata_alerts = list(json_response.get("suricata", {}).get("alerts", []))

        # get network data
        network_data = json_response.get("network", {})
        uri = [(network["uri"]) for network in network_data.get("http", [])]
        domains = [
            {"ip": network["ip"], "domain": network["domain"]}
            for network in network_data.get("domains", [])
        ]

        # extract all dns domain requested,...
        # .. can be used as IOC even if the conn was not successful
        dns_answered_list = []
        dns_data = network_data.get("dns", {})
        for dns_dict in dns_data:
            # if there are A records and we received an answer
            if (
                dns_dict.get("type", "") == "A"
                and dns_dict.get("answers", [])
                and dns_dict.get("request", "")
            ):
                dns_answered_list.append(dns_dict["request"])

        # other info
        info_data = json_response.get("info", {})
        # cuckoo magic score
        cuckoo_score = info_data.get("score", None)
        machine_data = info_data.get("machine", {})
        new_stats = info_data.get("new_stats", None)
        cuckoo_id = info_data.get("id", "")
        malfamily = json_response.get("malfamily", None)
        static = json_response.get("static", {})
        behavior = json_response.get("behavior", {})
        generic_behavior = behavior.get("generic", {})
        api_stats = behavior.get("apistats", {})
        extracted = json_response.get("extracted", {})
        processtree = behavior.get("processtree", {})
        anomaly = behavior.get("anomaly", {})
        debug = json_response.get("debug", {})
        file_data = json_response.get("target", {}).get("file", {})
        file_type = "".join(list(file_data.get("type", "")))
        yara = [yara_match["name"] for yara_match in file_data.get("yara", [])]

        result = {
            "link": f"{self.cuckoo_url}analysis/{cuckoo_id}/summary",
            "signatures": list_description_signatures,
            "signatures_detailed": list_detailed_signatures,
            "suricata_alerts": suricata_alerts,
            "potentially_malicious_urls": list_potentially_malicious_urls,
            "dyndns_domains": dyndns_domains,
            "answered_dns": dns_answered_list,
            "domains": domains,
            "uri": uri,
            "malscore": cuckoo_score,
            "malfamily": malfamily,
            "new_stats": new_stats,
            "file_type": file_type,
            "machine": machine_data,
            "id": cuckoo_id,
            "debug": debug,
            "yara": yara,
            "static": static,
            "behavior": {
                "generic_behavior": generic_behavior,
                "api_stats": api_stats,
                "extracted": extracted,
                "processtree": processtree,
                "anomaly": anomaly,
            },
        }

        logger.info(f"report generated for ({self.filename},{self.md5})")

        return result

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.Session.get",
                    return_value=MockResponse({"task": {"status": "reported"}}, 200),
                ),
                patch(
                    "requests.Session.post",
                    return_value=MockResponse({}, 200),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
