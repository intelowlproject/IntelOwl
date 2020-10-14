# for observable analyzers, if can customize the behavior based on:
# DISABLE_LOGGING_TEST to True -> logging disabled
# MOCK_CONNECTIONS to True -> connections to external analyzers are faked
import logging
import os
from unittest import skipIf
from unittest.mock import patch

from django.test import TestCase

from api_app.script_analyzers.observable_analyzers import (
    abuseipdb,
    censys,
    shodan,
    maxmind,
    greynoise,
    talos,
    tor,
    circl_pssl,
    circl_pdns,
    robtex,
    dnsdb,
    honeydb,
    hunter,
    mb_get,
    threatminer,
    auth0,
    securitytrails,
    cymru,
    tranco,
    whoisxmlapi,
    checkdmarc,
    urlscan,
)
from .mock_utils import (
    MockResponse,
    MockResponseNoOp,
    mock_connections,
    mocked_requests,
)
from .utils import (
    CommonTestCases_observables,
    CommonTestCases_ip_url_domain,
    CommonTestCases_ip_domain_hash,
    CommonTestCases_url_domain,
)

from intel_owl import settings

logger = logging.getLogger(__name__)
# disable logging library for travis
if settings.DISABLE_LOGGING_TEST:
    logging.disable(logging.CRITICAL)


def mocked_pypssl(*args, **kwargs):
    return MockResponseNoOp({}, 200)


def mocked_pypdns(*args, **kwargs):
    return MockResponseNoOp({}, 200)


def mocked_dnsdb_v2_request(*args, **kwargs):
    return MockResponse(
        json_data={},
        status_code=200,
        text='{"cond":"begin"}\n'
        '{"obj":{"count":1,"zone_time_first":1349367341,'
        '"zone_time_last":1440606099,"rrname":"mocked.data.net.",'
        '"rrtype":"A","bailiwick":"net.",'
        '"rdata":"0.0.0.0"}}\n'
        '{"cond":"limited","msg":"Result limit reached"}\n',
    )


@mock_connections(patch("requests.get", side_effect=mocked_requests))
@mock_connections(patch("requests.post", side_effect=mocked_requests))
class IPAnalyzersTests(
    CommonTestCases_ip_domain_hash,
    CommonTestCases_ip_url_domain,
    CommonTestCases_observables,
    TestCase,
):
    @staticmethod
    def get_params():
        return {
            "source": "test",
            "is_sample": False,
            "observable_name": os.environ.get("TEST_IP", "8.8.8.8"),
            "observable_classification": "ip",
            "force_privacy": False,
            "analyzers_requested": ["test"],
        }

    def test_abuseipdb(self, mock_get=None, mock_post=None):
        report = abuseipdb.AbuseIPDB(
            "AbuseIPDB",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        ).start()
        self.assertEqual(report.get("success", False), True)

    def test_auth0(self, mock_get=None, mock_post=None):
        report = auth0.Auth0(
            "Auth0",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        ).start()
        self.assertEqual(report.get("success", False), True)

    def test_securitytrails_ip(self, mock_get=None, mock_post=None):
        report = securitytrails.SecurityTrails(
            "Securitytrails_IP_Neighbours",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        ).start()
        self.assertEqual(report.get("success", False), True)

    def test_censys(self, mock_get=None, mock_post=None):
        report = censys.Censys(
            "Censys",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        ).start()
        self.assertEqual(report.get("success", False), True)

    def test_shodan(self, mock_get=None, mock_post=None):
        report = shodan.Shodan(
            "Shodan",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        ).start()
        self.assertEqual(report.get("success", False), True)

    def test_threatminer_ip(self, mock_get=None, mock_post=None):
        report = threatminer.Threatminer(
            "Threatminer",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        ).start()
        self.assertEqual(report.get("success", False), True)

    def test_honeydb_get(self, mock_get=None, mock_post=None):
        report = honeydb.HoneyDB(
            "HoneyDB_Get",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        ).start()
        self.assertEqual(report.get("success", False), True)

    def test_honeydb_scan_twitter(self, mock_get=None, mock_post=None):
        report = honeydb.HoneyDB(
            "HoneyDB_Scan_Twitter",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        ).start()
        self.assertEqual(report.get("success", False), True)

    @skipIf(settings.MOCK_CONNECTIONS, "not working without connection")
    def test_maxmind(self, mock_get=None, mock_post=None):
        report = maxmind.Maxmind(
            "MaxMindDB",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        ).start()
        self.assertEqual(report.get("success", False), True)

    def test_greynoisealpha(self, mock_get=None, mock_post=None):
        report = greynoise.GreyNoise(
            "GreyNoiseAlpha",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        ).start()
        self.assertEqual(report.get("success", False), True)

    def test_greynoise(self, mock_get=None, mock_post=None):
        report = greynoise.GreyNoise(
            "GreyNoise",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        ).start()
        self.assertEqual(report.get("success", False), True)

    def test_talos(self, mock_get=None, mock_post=None):
        report = talos.Talos(
            "TalosReputation",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        ).start()
        self.assertEqual(report.get("success", False), True)

    def test_tor(self, mock_get=None, mock_post=None):
        report = tor.Tor(
            "TorProject",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        ).start()
        self.assertEqual(report.get("success", False), True)

    @mock_connections(patch("pypssl.PyPSSL", side_effect=mocked_pypssl))
    def test_circl_pssl(self, mock_get=None, mock_post=None, sessions_get=None):
        report = circl_pssl.CIRCL_PSSL(
            "CIRCL_PSSL",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        ).start()
        self.assertEqual(report.get("success", False), True)

    def test_robtex_ip(self, mock_get=None, mock_post=None):
        report = robtex.Robtex(
            "Robtex_IP_Query",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        ).start()
        self.assertEqual(report.get("success", False), True)

    def test_robtex_rdns(self, mock_get=None, mock_post=None):
        report = robtex.Robtex(
            "Robtex_Reverse_PDNS_Query",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        ).start()
        self.assertEqual(report.get("success", False), True)

    @mock_connections(patch("requests.get", side_effect=mocked_dnsdb_v2_request))
    def test_dnsdb(self, mock_get=None, mock_post=None, mock_text_response=None):
        report = dnsdb.DNSdb(
            "DNSDB",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        ).start()
        self.assertEqual(report.get("success", False), True)

    def test_whoisxmlapi_ip(self, mock_get=None, mock_post=None):
        report = whoisxmlapi.Whoisxmlapi(
            "Whoisxmlapi_ip",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        ).start()
        self.assertEqual(report.get("success", False), True)


@mock_connections(patch("requests.get", side_effect=mocked_requests))
@mock_connections(patch("requests.post", side_effect=mocked_requests))
class DomainAnalyzersTests(
    CommonTestCases_ip_domain_hash,
    CommonTestCases_ip_url_domain,
    CommonTestCases_url_domain,
    CommonTestCases_observables,
    TestCase,
):
    @staticmethod
    def get_params():
        return {
            "source": "test",
            "is_sample": False,
            "observable_name": os.environ.get("TEST_DOMAIN", "www.google.com"),
            "observable_classification": "domain",
            "force_privacy": False,
            "analyzers_requested": ["test"],
        }

    def test_tranco(self, mock_get=None, mock_post=None):
        report = tranco.Tranco(
            "Tranco",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        ).start()
        self.assertEqual(report.get("success", False), True)

    def test_securitytrails_domain(self, mock_get=None, mock_post=None):
        report = securitytrails.SecurityTrails(
            "Securitytrails_Details",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        ).start()
        self.assertEqual(report.get("success", False), True)

    def test_hunter(self, mock_get=None, mock_post=None):
        report = hunter.Hunter(
            "Hunter",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        ).start()
        self.assertEqual(report.get("success", False), True)

    def test_threatminer_domain(self, mock_get=None, mock_post=None):
        report = threatminer.Threatminer(
            "Threatminer",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        ).start()
        self.assertEqual(report.get("success", False), True)

    @mock_connections(patch("pypdns.PyPDNS", side_effect=mocked_pypdns))
    def test_circl_pdns(self, mock_get=None, mock_post=None, sessions_get=None):
        report = circl_pdns.CIRCL_PDNS(
            "CIRCL_PDNS",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        ).start()
        self.assertEqual(report.get("success", False), True)

    def test_robtex_fdns(self, mock_get=None, mock_post=None):
        report = robtex.Robtex(
            "Robtex_Forward_PDNS_Query",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        ).start()
        self.assertEqual(report.get("success", False), True)

    @mock_connections(patch("requests.get", side_effect=mocked_dnsdb_v2_request))
    def test_dnsdb(self, mock_get=None, mock_post=None, mock_text_response=None):
        report = dnsdb.DNSdb(
            "DNSDB",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        ).start()
        self.assertEqual(report.get("success", False), True)

    def test_whoisxmlapi_domain(self, mock_get=None, mock_post=None):
        report = whoisxmlapi.Whoisxmlapi(
            "Whoisxmlapi_domain",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        ).start()
        self.assertEqual(report.get("success", False), True)

    def test_checkdmarc(self, mock_get=None, mock_post=None):
        report = checkdmarc.CheckDMARC(
            "CheckDMARC",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        ).start()

        self.assertEqual(report.get("success", False), True)


@mock_connections(patch("requests.get", side_effect=mocked_requests))
@mock_connections(patch("requests.post", side_effect=mocked_requests))
class URLAnalyzersTests(
    CommonTestCases_ip_url_domain,
    CommonTestCases_url_domain,
    CommonTestCases_observables,
    TestCase,
):
    @staticmethod
    def get_params():
        return {
            "source": "test",
            "is_sample": False,
            "observable_name": os.environ.get(
                "TEST_URL", "https://www.honeynet.org/projects/active/intel-owl/"
            ),
            "observable_classification": "url",
            "force_privacy": False,
            "analyzers_requested": ["test"],
        }

    @mock_connections(patch("pypdns.PyPDNS", side_effect=mocked_pypdns))
    def test_circl_pdns(self, mock_get=None, mock_post=None, sessions_get=None):
        report = circl_pdns.CIRCL_PDNS(
            "CIRCL_PDNS",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        ).start()
        self.assertEqual(report.get("success", False), True)

    @mock_connections(
        patch(
            "requests.Session.post",
            side_effect=lambda *args, **kwargs: MockResponse({"api": "test"}, 200),
        )
    )
    @mock_connections(patch("requests.Session.get", side_effect=mocked_requests))
    def test_urlscan_submit_result(self, *args):
        report = urlscan.UrlScan(
            "UrlScan_Submit_Result",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {"urlscan_analysis": "submit_result"},
        ).start()
        self.assertEqual(report.get("success", False), True)

    def test_robtex_fdns(self, mock_get=None, mock_post=None):
        report = robtex.Robtex(
            "Robtex_Forward_PDNS_Query",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        ).start()
        self.assertEqual(report.get("success", False), True)


@mock_connections(patch("requests.get", side_effect=mocked_requests))
@mock_connections(patch("requests.post", side_effect=mocked_requests))
class HashAnalyzersTests(
    CommonTestCases_ip_domain_hash, CommonTestCases_observables, TestCase
):
    @staticmethod
    def get_params():
        return {
            "source": "test",
            "is_sample": False,
            "observable_name": os.environ.get(
                "TEST_MD5", "446c5fbb11b9ce058450555c1c27153c"
            ),
            "observable_classification": "hash",
            "force_privacy": False,
            "analyzers_requested": ["test"],
        }

    def test_mb_get(self, mock_get=None, mock_post=None):
        report = mb_get.MB_GET(
            "MalwareBazaar_Get_Observable",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        ).start()
        self.assertEqual(report.get("success", False), True)

    def test_cymru_get(self, mock_get=None, mock_post=None):
        report = cymru.Cymru(
            "Cymru_Hash_Registry_Get_Observable",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        ).start()
        self.assertEqual(report.get("success", False), True)
