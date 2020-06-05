# for observable analyzers, if can customize the behavior based on:
# DISABLE_LOGGING_TEST to True -> logging disabled
# MOCK_CONNECTIONS to True -> connections to external analyzers are faked
import hashlib
import logging
import os
from unittest import skipIf
from unittest.mock import patch

from django.test import TestCase

from api_app.models import Job
from api_app.script_analyzers.observable_analyzers import (
    abuseipdb,
    censys,
    shodan,
    fortiguard,
    maxmind,
    greynoise,
    googlesf,
    otx,
    talos,
    tor,
    circl_pssl,
    circl_pdns,
    robtex,
    vt2_get,
    ha_get,
    vt3_get,
    misp,
    dnsdb,
    honeydb,
    hunter,
    mb_get,
    onyphe,
    threatminer,
    urlhaus,
    active_dns,
    auth0,
    securitytrails,
)
from intel_owl import settings

logger = logging.getLogger(__name__)
# disable logging library for travis
if settings.DISABLE_LOGGING_TEST:
    logging.disable(logging.CRITICAL)


# it is optional to mock requests
def mock_connections(decorator):
    return decorator if settings.MOCK_CONNECTIONS else lambda x: x


def mocked_requests(*args, **kwargs):
    class MockResponse:
        def __init__(self, json_data, status_code):
            self.json_data = json_data
            self.status_code = status_code
            self.text = ""
            self.content = b""

        def json(self):
            return self.json_data

        def raise_for_status(self):
            pass

    return MockResponse({}, 200)


def mocked_pymisp(*args, **kwargs):
    class MockResponse:
        def __init__(self, json_data, status_code):
            pass

        def search(self, **kwargs):
            return {}

    return MockResponse({}, 200)


def mocked_pypssl(*args, **kwargs):
    class MockResponse:
        def __init__(self, json_data, status_code):
            pass

        def query(self, ip):
            return {}

    return MockResponse({}, 200)


def mocked_pypdns(*args, **kwargs):
    class MockResponse:
        def __init__(self, json_data, status_code):
            pass

        def query(self, domain):
            return []

    return MockResponse({}, 200)


@mock_connections(patch("requests.get", side_effect=mocked_requests))
@mock_connections(patch("requests.post", side_effect=mocked_requests))
class IPAnalyzersTests(TestCase):
    def setUp(self):
        params = {
            "source": "test",
            "is_sample": False,
            "observable_name": os.environ.get("TEST_IP", "8.8.8.8"),
            "observable_classification": "ip",
            "force_privacy": False,
            "analyzers_requested": ["test"],
        }
        params["md5"] = hashlib.md5(
            params["observable_name"].encode("utf-8")
        ).hexdigest()
        test_job = Job(**params)
        test_job.save()
        self.job_id = test_job.id
        self.observable_name = test_job.observable_name
        self.observable_classification = test_job.observable_classification

    def test_abuseipdb(self, mock_get=None, mock_post=None):
        report = abuseipdb.run(
            "AbuseIPDB",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        )
        self.assertEqual(report.get("success", False), True)

    def test_auth0(self, mock_get=None, mock_post=None):
        report = auth0.run(
            "Auth0",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        )
        self.assertEqual(report.get("success", False), True)

    def test_securitytrails_ip(self, mock_get=None, mock_post=None):
        report = securitytrails.run(
            "Securitytrails_IP_Neighbours",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        )
        self.assertEqual(report.get("success", False), True)

    def test_censys(self, mock_get=None, mock_post=None):
        report = censys.run(
            "Censys",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        )
        self.assertEqual(report.get("success", False), True)

    def test_shodan(self, mock_get=None, mock_post=None):
        report = shodan.run(
            "Shodan",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        )
        self.assertEqual(report.get("success", False), True)

    def test_threatminer_ip(self, mock_get=None, mock_post=None):
        report = threatminer.run(
            "Threatminer",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        )
        self.assertEqual(report.get("success", False), True)

    def test_honeydb_get(self, mock_get=None, mock_post=None):
        report = honeydb.run(
            "HoneyDB_Get",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        )
        self.assertEqual(report.get("success", False), True)

    def test_honeydb_scan_twitter(self, mock_get=None, mock_post=None):
        report = honeydb.run(
            "HoneyDB_Scan_Twitter",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        )
        self.assertEqual(report.get("success", False), True)

    @skipIf(settings.MOCK_CONNECTIONS, "not working without connection")
    def test_maxmind(self, mock_get=None, mock_post=None):
        report = maxmind.run(
            "MaxMindDB",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        )
        self.assertEqual(report.get("success", False), True)

    def test_greynoisealpha(self, mock_get=None, mock_post=None):
        report = greynoise.run(
            "GreyNoiseAlpha",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        )
        self.assertEqual(report.get("success", False), True)

    def test_greynoise(self, mock_get=None, mock_post=None):
        report = greynoise.run(
            "GreyNoise",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        )
        self.assertEqual(report.get("success", False), True)

    def test_gsf(self, mock_get=None, mock_post=None):
        report = googlesf.run(
            "GoogleSafeBrowsing",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        )
        self.assertEqual(report.get("success", False), True)

    def test_otx(self, mock_get=None, mock_post=None):
        report = otx.run(
            "OTX", self.job_id, self.observable_name, self.observable_classification, {}
        )
        self.assertEqual(report.get("success", False), True)

    def test_talos(self, mock_get=None, mock_post=None):
        report = talos.run(
            "TalosReputation",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        )
        self.assertEqual(report.get("success", False), True)

    def test_tor(self, mock_get=None, mock_post=None):
        report = tor.run(
            "TorProject",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        )
        self.assertEqual(report.get("success", False), True)

    @mock_connections(patch("pypssl.PyPSSL", side_effect=mocked_pypssl))
    def test_circl_pssl(self, mock_get=None, mock_post=None, sessions_get=None):
        report = circl_pssl.run(
            "CIRCL_PSSL",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        )
        self.assertEqual(report.get("success", False), True)

    def test_robtex_ip(self, mock_get=None, mock_post=None):
        report = robtex.run(
            "Robtex_IP_Query",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        )
        self.assertEqual(report.get("success", False), True)

    def test_robtex_rdns(self, mock_get=None, mock_post=None):
        report = robtex.run(
            "Robtex_Reverse_PDNS_Query",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        )
        self.assertEqual(report.get("success", False), True)

    def test_dnsdb(self, mock_get=None, mock_post=None):
        report = dnsdb.run(
            "DNSDB",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        )
        self.assertEqual(report.get("success", False), True)

    def test_vt_get(self, mock_get=None, mock_post=None):
        report = vt2_get.run(
            "VT_v2_Get",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        )
        self.assertEqual(report.get("success", False), True)

    def test_ha_get(self, mock_get=None, mock_post=None):
        report = ha_get.run(
            "HybridAnalysis_Get_Observable",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        )
        self.assertEqual(report.get("success", False), True)

    def test_vt3_get(self, mock_get=None, mock_post=None):
        report = vt3_get.run(
            "VT_v3_Get",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        )
        self.assertEqual(report.get("success", False), True)

    @mock_connections(patch("pymisp.ExpandedPyMISP", side_effect=mocked_pymisp))
    def test_misp_first(self, mock_get=None, mock_post=None, mock_pymisp=None):
        report = misp.run(
            "MISP_FIRST",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {"api_key_name": "FIRST_MISP_API", "url_key_name": "FIRST_MISP_URL"},
        )
        self.assertEqual(report.get("success", False), True)

    def test_onyphe(self, mock_get=None, mock_post=None):
        report = onyphe.run(
            "ONYPHE",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        )
        self.assertEqual(report.get("success", False), True)

    def active_dns_classic_reverse(self, mock_get=None, mock_post=None):
        report = active_dns.run(
            "ActiveDNS_Classic_reverse",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {"service": "classic"},
        )

        self.assertEqual(report.get("success", False), True, f"report: {report}")


@mock_connections(patch("requests.get", side_effect=mocked_requests))
@mock_connections(patch("requests.post", side_effect=mocked_requests))
class DomainAnalyzersTests(TestCase):
    def setUp(self):
        params = {
            "source": "test",
            "is_sample": False,
            "observable_name": os.environ.get("TEST_DOMAIN", "www.google.com"),
            "observable_classification": "domain",
            "force_privacy": False,
            "analyzers_requested": ["test"],
        }
        params["md5"] = hashlib.md5(
            params["observable_name"].encode("utf-8")
        ).hexdigest()
        test_job = Job(**params)
        test_job.save()
        self.job_id = test_job.id
        self.observable_name = test_job.observable_name
        self.observable_classification = test_job.observable_classification

    def test_fortiguard(self, mock_get=None, mock_post=None):
        report = fortiguard.run(
            "Fortiguard",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        )
        self.assertEqual(report.get("success", False), True)

    def test_securitytrails_domain(self, mock_get=None, mock_post=None):
        report = securitytrails.run(
            "Securitytrails_Details",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        )
        self.assertEqual(report.get("success", False), True)

    def test_hunter(self, mock_get=None, mock_post=None):
        report = hunter.run(
            "Hunter",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        )
        self.assertEqual(report.get("success", False), True)

    def test_threatminer_domain(self, mock_get=None, mock_post=None):
        report = threatminer.run(
            "Threatminer",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        )
        self.assertEqual(report.get("success", False), True)

    def test_gsf(self, mock_get=None, mock_post=None):
        report = googlesf.run(
            "GoogleSafeBrowsing",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        )
        self.assertEqual(report.get("success", False), True)

    def test_otx(self, mock_get=None, mock_post=None):
        report = otx.run(
            "OTX", self.job_id, self.observable_name, self.observable_classification, {}
        )
        self.assertEqual(report.get("success", False), True)

    @mock_connections(patch("pypdns.PyPDNS", side_effect=mocked_pypdns))
    def test_circl_pdns(self, mock_get=None, mock_post=None, sessions_get=None):
        report = circl_pdns.run(
            "CIRCL_PDNS",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        )
        self.assertEqual(report.get("success", False), True)

    def test_robtex_fdns(self, mock_get=None, mock_post=None):
        report = robtex.run(
            "Robtex_Forward_PDNS_Query",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        )
        self.assertEqual(report.get("success", False), True)

    def test_dnsdb(self, mock_get=None, mock_post=None):
        report = dnsdb.run(
            "DNSDB",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        )
        self.assertEqual(report.get("success", False), True)

    def test_vt_get(self, mock_get=None, mock_post=None):
        report = vt2_get.run(
            "VT_v2_Get",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        )
        self.assertEqual(report.get("success", False), True)

    def test_ha_get(self, mock_get=None, mock_post=None):
        report = ha_get.run(
            "HybridAnalysis_Get_Observable",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        )
        self.assertEqual(report.get("success", False), True)

    def test_vt3_get(self, mock_get=None, mock_post=None):
        report = vt3_get.run(
            "VT_v3_Get",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        )
        self.assertEqual(report.get("success", False), True)

    @mock_connections(patch("pymisp.ExpandedPyMISP", side_effect=mocked_pymisp))
    def test_misp_first(self, mock_get=None, mock_post=None, mock_pymisp=None):
        report = misp.run(
            "MISP_FIRST",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {"api_key_name": "FIRST_MISP_API", "url_key_name": "FIRST_MISP_URL"},
        )
        self.assertEqual(report.get("success", False), True)

    def test_onyphe(self, mock_get=None, mock_post=None):
        report = onyphe.run(
            "ONYPHE",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        )
        self.assertEqual(report.get("success", False), True)

    def test_urlhaus(self, mock_get=None, mock_post=None):
        report = urlhaus.run(
            "URLhaus",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        )
        self.assertEqual(report.get("success", False), True)

    def test_active_dns(self, mock_get=None, mock_post=None):
        # Google
        google_report = active_dns.run(
            "ActiveDNS_Google",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {"service": "google"},
        )

        self.assertEqual(
            google_report.get("success", False), True, f"google_report: {google_report}"
        )

        # CloudFlare
        cloudflare_report = active_dns.run(
            "ActiveDNS_CloudFlare",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {"service": "cloudflare"},
        )

        self.assertEqual(
            cloudflare_report.get("success", False),
            True,
            f"cloudflare_report: {cloudflare_report}",
        )
        # Classic
        classic_report = active_dns.run(
            "ActiveDNS_Classic",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {"service": "classic"},
        )

        self.assertEqual(
            classic_report.get("success", False),
            True,
            f"classic_report: {classic_report}",
        )

    def test_cloudFlare_malware(self, mock_get=None, mock_post=None):
        report = active_dns.run(
            "ActiveDNS_CloudFlare_Malware",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {"service": "cloudflare_malware"},
        )

        self.assertEqual(report.get("success", False), True, f"report: {report}")


@mock_connections(patch("requests.get", side_effect=mocked_requests))
@mock_connections(patch("requests.post", side_effect=mocked_requests))
class URLAnalyzersTests(TestCase):
    def setUp(self):
        params = {
            "source": "test",
            "is_sample": False,
            "observable_name": os.environ.get(
                "TEST_URL", "https://www.google.com/search?test"
            ),
            "observable_classification": "url",
            "force_privacy": False,
            "analyzers_requested": ["test"],
        }
        params["md5"] = hashlib.md5(
            params["observable_name"].encode("utf-8")
        ).hexdigest()
        test_job = Job(**params)
        test_job.save()
        self.job_id = test_job.id
        self.observable_name = test_job.observable_name
        self.observable_classification = test_job.observable_classification

    def test_fortiguard(self, mock_get=None, mock_post=None):
        report = fortiguard.run(
            "Fortiguard",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        )
        self.assertEqual(report.get("success", False), True)

    def test_gsf(self, mock_get=None, mock_post=None):
        report = googlesf.run(
            "GoogleSafeBrowsing",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        )
        self.assertEqual(report.get("success", False), True)

    def test_otx(self, mock_get=None, mock_post=None):
        report = otx.run(
            "OTX", self.job_id, self.observable_name, self.observable_classification, {}
        )
        self.assertEqual(report.get("success", False), True)

    @mock_connections(patch("pypdns.PyPDNS", side_effect=mocked_pypdns))
    def test_circl_pdns(self, mock_get=None, mock_post=None, sessions_get=None):
        report = circl_pdns.run(
            "CIRCL_PDNS",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        )
        self.assertEqual(report.get("success", False), True)

    def test_robtex_fdns(self, mock_get=None, mock_post=None):
        report = robtex.run(
            "Robtex_Forward_PDNS_Query",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        )
        self.assertEqual(report.get("success", False), True)

    def test_vt_get(self, mock_get=None, mock_post=None):
        report = vt2_get.run(
            "VT_v2_Get",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        )
        self.assertEqual(report.get("success", False), True)

    def test_vt3_get(self, mock_get=None, mock_post=None):
        report = vt3_get.run(
            "VT_v3_Get",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        )
        self.assertEqual(report.get("success", False), True)

    def test_onyphe(self, mock_get=None, mock_post=None):
        report = onyphe.run(
            "ONYPHE",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        )
        self.assertEqual(report.get("success", False), True)

    def test_urlhaus(self, mock_get=None, mock_post=None):
        report = urlhaus.run(
            "URLhaus",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        )
        self.assertEqual(report.get("success", False), True)


@mock_connections(patch("requests.get", side_effect=mocked_requests))
@mock_connections(patch("requests.post", side_effect=mocked_requests))
class HashAnalyzersTests(TestCase):
    def setUp(self):
        params = {
            "source": "test",
            "is_sample": False,
            "observable_name": os.environ.get(
                "TEST_MD5", "446c5fbb11b9ce058450555c1c27153c"
            ),
            "observable_classification": "hash",
            "force_privacy": False,
            "analyzers_requested": ["test"],
        }
        params["md5"] = hashlib.md5(
            params["observable_name"].encode("utf-8")
        ).hexdigest()
        test_job = Job(**params)
        test_job.save()
        self.job_id = test_job.id
        self.observable_name = test_job.observable_name
        self.observable_classification = test_job.observable_classification

    def test_otx(self, mock_get=None, mock_post=None):
        report = otx.run(
            "OTX", self.job_id, self.observable_name, self.observable_classification, {}
        )
        self.assertEqual(report.get("success", False), True)

    def test_vt_get(self, mock_get=None, mock_post=None):
        report = vt2_get.run(
            "VT_v2_Get",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        )
        self.assertEqual(report.get("success", False), True)

    def test_ha_get(self, mock_get=None, mock_post=None):
        report = ha_get.run(
            "HybridAnalysis_Get_Observable",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        )
        self.assertEqual(report.get("success", False), True)

    def test_vt3_get(self, mock_get=None, mock_post=None):
        report = vt3_get.run(
            "VT_v3_Get",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        )
        self.assertEqual(report.get("success", False), True)

    @mock_connections(patch("pymisp.ExpandedPyMISP", side_effect=mocked_pymisp))
    def test_misp_first(self, mock_get=None, mock_post=None, mock_pymisp=None):
        report = misp.run(
            "MISP_FIRST",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {"api_key_name": "FIRST_MISP_API", "url_key_name": "FIRST_MISP_URL"},
        )
        self.assertEqual(report.get("success", False), True)

    def test_mb_get(self, mock_get=None, mock_post=None):
        report = mb_get.run(
            "MalwareBazaar_Get_Observable",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        )
        self.assertEqual(report.get("success", False), True)
