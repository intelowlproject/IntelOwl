import hashlib
from abc import ABCMeta
from unittest.mock import patch

from api_app.models import Job
from api_app.script_analyzers.observable_analyzers import (
    pulsedive,
    otx,
    vt2_get,
    vt3_get,
    misp,
    onyphe,
    ha_get,
    thug_url,
    urlhaus,
    fortiguard,
    intelx,
    urlscan,
    mb_google,
    inquest,
)

from api_app.script_analyzers.observable_analyzers.dns.dns_resolvers import (
    classic_dns_resolver,
    cloudflare_dns_resolver,
    google_dns_resolver,
    quad9_dns_resolver,
)

from api_app.script_analyzers.observable_analyzers.dns.dns_malicious_detectors import (
    cloudflare_malicious_detector,
    googlesf,
    quad9_malicious_detector,
)

from .mock_utils import (
    mock_connections,
    mocked_requests_noop,
    MockResponse,
    mocked_requests,
)


# Abstract Base classes constructed for most common occuring combinations
# to avoid duplication of code
class CommonTestCases_observables(metaclass=ABCMeta):
    """
    Includes tests which are common for all types of observables.
    """

    def setUp(self):
        params = self.get_params()
        params["md5"] = hashlib.md5(
            params["observable_name"].encode("utf-8")
        ).hexdigest()
        test_job = Job(**params)
        test_job.save()
        self.job_id = test_job.id
        self.observable_name = test_job.observable_name
        self.observable_classification = test_job.observable_classification

    def test_vt3_get(self, mock_get=None, mock_post=None):
        report = vt3_get.VirusTotalv3(
            "VT_v3_Get",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {"max_tries": 1},
        ).start()
        self.assertEqual(report.get("success", False), True)

    def test_vt2_get(self, mock_get=None, mock_post=None):
        report = vt2_get.VirusTotalv2(
            "VT_v2_Get",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        ).start()
        self.assertEqual(report.get("success", False), True)

    def test_otx(self, mock_get=None, mock_post=None):
        report = otx.OTX(
            "OTX", self.job_id, self.observable_name, self.observable_classification, {}
        ).start()
        self.assertEqual(report.get("success", False), True)

    def test_InQuest_IOCdb(self, mock_get=None, mock_post=None):
        report = inquest.InQuest(
            "InQuest_IOCdb",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {"inquest_analysis": "iocdb_search"},
        ).start()
        self.assertEqual(report.get("success", False), True)

    def test_InQuest_REPdb(self, mock_get=None, mock_post=None):
        report = inquest.InQuest(
            "InQuest_REPdb",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {"inquest_analysis": "repdb_search"},
        ).start()
        self.assertEqual(report.get("success", False), True)

    def test_InQuest_DFI(self, mock_get=None, mock_post=None):
        report = inquest.InQuest(
            "InQuest_DFI",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {"inquest_analysis": "dfi_search"},
        ).start()
        self.assertEqual(report.get("success", False), True)

    def test_pulsevide(self, mock_get=None, mock_post=None):
        report = pulsedive.Pulsedive(
            "Pulsedive_Active_IOC",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        ).start()
        self.assertEqual(report.get("success", False), True)

    @mock_connections(
        patch(
            "requests.Session.post",
            side_effect=lambda *args, **kwargs: MockResponse({"id": 1}, 200),
        )
    )
    @mock_connections(
        patch(
            "requests.Session.get",
            side_effect=lambda *args, **kwargs: MockResponse({"selectors": []}, 200),
        )
    )
    def test_intelx(self, *args):
        report = intelx.IntelX(
            "IntelX_Phonebook",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        ).start()
        self.assertEqual(report.get("success", False), True)

    @mock_connections(patch("pymisp.ExpandedPyMISP", side_effect=mocked_requests_noop))
    def test_misp_first(self, *args):
        report = misp.MISP(
            "MISP_FIRST",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {"api_key_name": "FIRST_MISP_API", "url_key_name": "FIRST_MISP_URL"},
        ).start()
        self.assertEqual(report.get("success", False), True)

    @mock_connections(patch("requests.Session.get", side_effect=mocked_requests))
    def test_urlscan_search(self, *args):
        if self.observable_classification == "url":
            self.observable_name = "https://www.honeynet.org/"
        report = urlscan.UrlScan(
            "UrlScan_Search",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {"urlscan_analysis": "search"},
        ).start()
        self.assertEqual(report.get("success", False), True)


class CommonTestCases_ip_url_domain(metaclass=ABCMeta):
    """
    Tests which are common for IP, URL, domain types.
    """

    def test_classic_dns_resolver(self, mock_get=None, mock_post=None):
        report = classic_dns_resolver.ClassicDNSResolver(
            "ClassicDNSResolver",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        ).start()
        self.assertEqual(report.get("success", False), True)

    def test_gsf(self, mock_get=None, mock_post=None):
        report = googlesf.GoogleSF(
            "GoogleSafeBrowsing",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        ).start()
        self.assertEqual(report.get("success", False), True)

    def test_onyphe(self, mock_get=None, mock_post=None):
        report = onyphe.Onyphe(
            "ONYPHE",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        ).start()
        self.assertEqual(report.get("success", False), True)

    def test_mb_google(self, mock_get=None, mock_post=None):
        report = mb_google.MB_GOOGLE(
            "MalwareBazaar_Google_Observable",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        ).start()
        self.assertEqual(report.get("success", False), True)


class CommonTestCases_ip_domain_hash(metaclass=ABCMeta):
    """
    Tests which are common for IP, domain, hash types.
    """

    def test_ha_get(self, mock_get=None, mock_post=None):
        report = ha_get.HybridAnalysisGet(
            "HybridAnalysis_Get_Observable",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        ).start()
        self.assertEqual(report.get("success", False), True)


class CommonTestCases_url_domain(metaclass=ABCMeta):
    """
    Tests which are common for URL and Domain types.
    """

    def test_cloudflare_dns_resolver(self, mock_get=None, mock_post=None):
        report = cloudflare_dns_resolver.CloudFlareDNSResolver(
            "CloudFlareDNSResolver",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        ).start()
        self.assertEqual(report.get("success", False), True)

    def test_cloudflare_malicious_detector(self, mock_get=None, mock_post=None):
        report = cloudflare_malicious_detector.CloudFlareMaliciousDetector(
            "CloudFlareMaliciousDetector",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        ).start()
        self.assertEqual(report.get("success", False), True)

    def test_fortiguard(self, mock_get=None, mock_post=None):
        report = fortiguard.Fortiguard(
            "Fortiguard",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        ).start()
        self.assertEqual(report.get("success", False), True)

    def test_google_dns_resolver(self, mock_get=None, mock_post=None):
        report = google_dns_resolver.GoogleDNSResolver(
            "GoogleDNSResolver",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        ).start()
        self.assertEqual(report.get("success", False), True)

    def test_quad9_dns_resolver(self, mock_get=None, mock_post=None):
        report = quad9_dns_resolver.Quad9DNSResolver(
            "Quad9DNSResolver",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        ).start()
        self.assertEqual(report.get("success", False), True)

    def test_quad9_malicious_detector(self, mock_get=None, mock_post=None):
        report = quad9_malicious_detector.Quad9MaliciousDetector(
            "Quad9MaliciousDetector",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        ).start()
        self.assertEqual(report.get("success", False), True)

    def test_urlhaus(self, mock_get=None, mock_post=None):
        report = urlhaus.URLHaus(
            "URLhaus",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            {},
        ).start()
        self.assertEqual(report.get("success", False), True)

    def test_thug_url(self, mock_get=None, mock_post=None):
        additional_params = {"test": True}
        report = thug_url.ThugUrl(
            "Thug_URL_Info",
            self.job_id,
            self.observable_name,
            self.observable_classification,
            additional_params,
        ).start()
        self.assertEqual(report.get("success", False), True)
