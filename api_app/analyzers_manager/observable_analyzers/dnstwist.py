# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import json
import logging
import subprocess
from ipaddress import AddressValueError, IPv4Address
from shutil import which
from unittest.mock import patch
from urllib.parse import urlparse

from django.conf import settings

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from tests.mock_utils import if_mock_connections

logger = logging.getLogger(__name__)


class MockPopen:
    def communicate(self):
        return (b"{}", b"")


class DNStwist(classes.ObservableAnalyzer):
    DNS_TWIST_PATH = settings.BASE_DIR / "dnstwist-dictionaries"
    COMMAND: str = "dnstwist"

    tld_dict: str
    language_dict: str
    fuzzy_hash: str
    fuzzy_hash_url: str
    mxcheck: bool
    user_agent: str
    nameservers: str

    def run(self):
        if not which(self.COMMAND):
            raise AnalyzerRunException("dnstwist not installed!")

        domain = self.observable_name

        if self.observable_classification == self.ObservableTypes.URL:
            domain = urlparse(self.observable_name).hostname
            try:
                IPv4Address(domain)
            except AddressValueError:
                pass
            else:
                raise AnalyzerRunException(
                    "URL with an IP address instead of a domain cannot be analyzed"
                )

        args = [self.COMMAND, "--registered", "--format", "json"]
        if self.fuzzy_hash:
            args.append("--lsh")
            args.append(self.fuzzy_hash)
            if self.fuzzy_hash_url:
                args.append("--lsh-url")
                args.append(self.fuzzy_hash_url)
        if self.mxcheck:
            args.append("--mxcheck")
        if self.tld_dict:
            args.append("--tld")
            args.append(self.DNS_TWIST_PATH / self.tld_dict)
        if self.language_dict:
            args.append("--dictionary")
            args.append(self.DNS_TWIST_PATH / self.language_dict)
        if self.nameservers:
            args.append("--nameservers")
            args.append(self.nameservers)
        if self.user_agent:
            args.append("--useragent")
            args.append(self.user_agent)

        args.append(domain)

        process = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stdout, stderr = process.communicate()
        logger.warning(stderr.decode("utf-8"))
        final_report = dict()
        final_report["error"] = stderr.decode("utf-8")

        dns_str = stdout.decode("utf-8")

        try:
            if dns_str:
                data = json.loads(dns_str)
                final_report["data"] = data
        except ValueError as e:
            raise AnalyzerRunException(f"dns_str: {dns_str}. Error: {e}")

        return final_report

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "subprocess.Popen",
                    return_value=MockPopen(),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
