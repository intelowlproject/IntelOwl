# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import subprocess
import json
import logging

from shutil import which
from urllib.parse import urlparse
from ipaddress import AddressValueError, IPv4Address

from api_app.exceptions import AnalyzerRunException
from api_app.analyzers_manager import classes

logger = logging.getLogger(__name__)


class DNStwist(classes.ObservableAnalyzer):
    command: str = "dnstwist"
    dictionary_base_path: str = "/opt/deploy/dnstwist-dictionaries/"

    def set_params(self, params):
        self._ssdeep = params.get("ssdeep", False)
        self._mxcheck = params.get("mxcheck", False)
        self._tld = params.get("tld", False)
        self._tld_dict = params.get("tld_dict", "abused_tlds.dict")

    def run(self):
        if not which(self.command):
            raise AnalyzerRunException("dnstwist not installed!")

        domain = self.observable_name

        if self.observable_classification == self.ObservableTypes.URL.value:
            domain = urlparse(self.observable_name).hostname
            try:
                IPv4Address(domain)
            except AddressValueError:
                pass
            else:
                raise AnalyzerRunException(
                    "URL with an IP address instead of a domain cannot be analyzed"
                )

        final_report = {
            "ssdeep": self._ssdeep,
            "mxcheck": self._mxcheck,
            "tld": self._tld,
        }

        args = [self.command, "--registered", "--format", "json"]
        if self._ssdeep:
            args.append("--ssdeep")
        if self._mxcheck:
            args.append("--mxcheck")
        if self._tld:
            args.append("--tld")
            args.append(self.dictionary_base_path + self._tld_dict)

        args.append(domain)

        process = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stdout, stderr = process.communicate()
        logger.warning(stderr.decode("utf-8"))
        final_report["error"] = stderr.decode("utf-8")

        dns_report = stdout.decode("utf-8"), stderr
        dns_str = dns_report[0]

        try:
            if dns_str:
                data = json.loads(dns_str)
                final_report["data"] = data
        except ValueError as e:
            raise AnalyzerRunException(f"dns_str: {dns_str}. Error: {e}")

        return final_report
