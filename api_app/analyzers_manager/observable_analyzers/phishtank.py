# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import base64
import logging
from urllib.parse import urlparse

import requests

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from tests.mock_utils import MockUpResponse, if_mock_connections, patch

logger = logging.getLogger(__name__)


class Phishtank(ObservableAnalyzer):
    _api_key_name: str

    def run(self):
        headers = {"User-Agent": "phishtank/IntelOwl"}
        observable_to_analyze = self.observable_name
        if self.observable_classification == self.ObservableTypes.DOMAIN:
            observable_to_analyze = "http://" + self.observable_name
        parsed = urlparse(observable_to_analyze)
        if not parsed.path:
            observable_to_analyze += "/"
        data = {
            "url": base64.b64encode(observable_to_analyze.encode("utf-8")),
            "format": "json",
        }
        # optional API key
        if not hasattr(self, "_api_key_name"):
            logger.warning(f"{self.__repr__()} -> Continuing w/o API key..")
        else:
            data["app_key"] = self._api_key_name
        try:
            resp = requests.post(
                "https://checkurl.phishtank.com/checkurl/", data=data, headers=headers
            )
            resp.raise_for_status()
            result = resp.json()
        except requests.RequestException as e:
            raise AnalyzerRunException(e)
        return result

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.post",
                    return_value=MockUpResponse({}, 200),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)


"""

IntelOwl logov5.2.3
Home
Dashboard
Jobs
Plugins
Scan
4
SB
Organization
Organization Config
 Invitations
certego's plugin configuration
Note: Your plugin configuration overrides your organization's configuration.
 Parameters
 Secrets

Analyzer

AbuseIPDB

api_key_name
**********

Analyzer

Auth0

api_key_name
**********

Analyzer

CIRCLPassiveDNS

pdns_credentials
**********

Analyzer

CIRCLPassiveSSL

pdns_credentials
**********

Analyzer

Censys_Search

api_id_name
**********

Analyzer

Censys_Search

api_secret_name
**********

Analyzer

Cuckoo_Scan

url_key_name
**********

Analyzer

Dehashed_Search

api_key_name
**********

Analyzer

DNSDB

api_key_name
**********

Analyzer

Dragonfly_Emulation_PE

api_key_name
**********

Analyzer

Dragonfly_Emulation_PE

url_key_name
**********

Analyzer

Dragonfly_Emulation_PE

certificate_path_name
**********

Analyzer

GoogleSafebrowsing

api_key_name
**********

Analyzer

HybridAnalysis_Get_File

api_key_name
**********

Analyzer

Intezer_Get

api_key_name
**********

Analyzer

Intezer_Scan

api_key_name
**********

Analyzer

MISPFIRST_Check_Hash

api_key_name
**********

Analyzer

MISPFIRST

url_key_name
**********

Analyzer

MaxMindGeoIP

api_key_name
**********

Analyzer

MWDB_Get

api_key_name
**********

Analyzer

MWDB_Scan

api_key_name
**********

Analyzer

ONYPHE

api_key_name
**********

Analyzer

OTX_Check_Hash

api_key_name
**********

Analyzer

Phishtank

api_key_name
**********

Analyzer

Pulsedive

api_key_name
**********

Analyzer

Quokka_PDNS_Wildcard_Left

api_key_name
**********

Analyzer

Quokka_PDNS_Wildcard_Left

url_key_name
**********

Analyzer

Shodan_Honeyscore

api_key_name
**********

Analyzer

UnpacMe

api_key_name
**********

Analyzer

VirusTotal_v3_Intelligence_Search

api_key_name
**********

Analyzer

VirusTotal_v3_Get_File

api_key_name
**********

Analyzer

XForceExchange

api_key_name
**********

Analyzer

XForceExchange

api_password_name
**********

Analyzer

Triage_Search

api_key_name
**********

Analyzer

Triage_Scan

api_key_name
**********

Analyzer

YARAify_File_Scan

api_key_identifier
**********

Analyzer

Stalkphish

api_key_name
**********

Analyzer

GoogleWebRisk

service_account_json
**********

Analyzer

Yara

private_repositories
**********

Analyzer

Crowdsec

api_key_name
**********

Analyzer

SublimeSecurity

url
**********

Analyzer

SublimeSecurity

api_key
**********

Analyzer

SublimeSecurity

message_source_id
**********

Connector

Quokka

url
**********

Connector

Quokka

api_key_name
**********

Connector

Quokka

engine_url
**********

Analyzer

DNSDB_SIE

api_key_name
**********

Analyzer

DNSDB_SIE_Names

api_key_name
**********

Analyzer

DNSDB_SIE_Wildcard_Left

api_key_name
**********

Analyzer

HybridAnalysis_Get_Observable

api_key_name
**********

Analyzer

VirusTotal_v3_Get_Observable

api_key_name
08043cd5c1ed59fb025737eeef91caf1e9f38cff0f4392e2b5027a1399f20ce0

Analyzer

Dragonfly_Emulation_ELF

api_key_name
**********

Analyzer

OTXQuery

api_key_name
**********

Analyzer

Quokka_RDNS_Names

url_key_name
**********

Analyzer

Quokka_PDNS

url_key_name
**********

Analyzer

Quokka_RDNS

url_key_name
**********

Analyzer

Quokka_PDNS

api_key_name
**********

Analyzer

Quokka_RDNS

api_key_name
**********

Analyzer

Quokka_RDNS_Names

api_key_name
**********

Analyzer

MISPFIRST_Check_Hash

url_key_name
**********

Analyzer

MISPFIRST

api_key_name
**********

Connector

Quokka

engine_api_key_name
**********

Analyzer

CapeSandbox

api_key_name
**********

Analyzer

CapeSandbox

url_key_name
**********

Analyzer

CapeSandbox

certificate
**********

Visualizer

Quokka_Domain_Url

quokka_base_url
**********

Visualizer

Quokka_Ip

quokka_base_url
**********

Visualizer

Quokka_Hash

quokka_base_url
**********

Visualizer

Quokka_File

quokka_base_url
**********

Visualizer

Quokka_Static_File

quokka_base_url
**********

Visualizer

Sample_Static_Analysis

quokka_base_url
**********

Visualizer

Quokka_File

capybox_base_url
**********

Visualizer

Quokka_Hash

capybox_base_url
**********

Visualizer

Quokka_Static_File

capybox_base_url
**********

Visualizer

Sample_Static_Analysis

capybox_base_url
**********

Visualizer

Quokka_Observable

quokka_base_url
**********

Analyzer

DNS0_rrsets_data

api_key
**********

Analyzer

DNS0_rrsets_name

api_key
**********

Analyzer

DNS0_names

api_key
**********

Visualizer

Quokka_Observable

capybox_base_url
**********
15

"""
