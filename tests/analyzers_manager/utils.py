from unittest import skipIf
from unittest.mock import patch

from intel_owl import settings

from ..mock_utils import (
    MockResponse,
    MockResponseNoOp,
    mock_connections,
    mocked_requests,
    mocked_requests_noop,
)


######### MOCK UTILS ##########


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


def mocked_triage_get(*args, **kwargs):
    return MockResponse({"tasks": {"task_1": {}, "task_2": {}}, "data": []}, 200)


def mocked_triage_post(*args, **kwargs):
    return MockResponse({"id": "sample_id", "status": "pending"}, 200)


def mocked_firehol_iplist(*args, **kwargs):
    return MockResponse(
        json_data={},
        status_code=200,
        text="""0.0.0.0/8\n
            1.10.16.0/20\n
            1.19.0.0/16\n
            3.90.198.217\n""",
    )


#### mocks functions - analyzer map ####


analyzer_mock_fnsmap = {
    "MaxMindGeoIP": [
        skipIf(settings.MOCK_CONNECTIONS, "not working without connection")
    ],
    "FireHol_IPList": [
        mock_connections(patch("requests.get", side_effect=mocked_firehol_iplist))
    ],
    "CIRCLPassiveSSL": [
        mock_connections(patch("pypssl.PyPSSL", side_effect=mocked_pypssl)),
    ],
    "DNSDB": [
        mock_connections(patch("requests.get", side_effect=mocked_dnsdb_v2_request))
    ],
    "CIRCLPassiveDNS": [
        mock_connections(patch("pypdns.PyPDNS", side_effect=mocked_pypdns))
    ],
    "UrlScan_Submit_Result": [
        mock_connections(
            patch(
                "requests.Session.post",
                side_effect=lambda *args, **kwargs: MockResponse({"api": "test"}, 200),
            )
        ),
        mock_connections(patch("requests.Session.get", side_effect=mocked_requests)),
    ],
    "UrlScan_Search": [
        mock_connections(
            patch(
                "requests.Session.post",
                side_effect=lambda *args, **kwargs: MockResponse({"api": "test"}, 200),
            )
        ),
        mock_connections(patch("requests.Session.get", side_effect=mocked_requests)),
    ],
    "Darksearch_Query": [
        mock_connections(
            patch(
                "darksearch.Client.search",
                side_effect=lambda *args, **kwargs: [
                    {"total": 1, "last_page": 0, "data": []}
                ],
            )
        )
    ],
    "Triage_Search": [
        mock_connections(patch("requests.Session.get", side_effect=mocked_triage_get)),
        mock_connections(
            patch("requests.Session.post", side_effect=mocked_triage_post)
        ),
    ],
    "OTXQuery": [
        mock_connections(
            patch(
                "requests.Session.get",
                side_effect=mocked_requests,
            )
        )
    ],
    "OTX_Check_Hash": [
        mock_connections(
            patch(
                "requests.Session.get",
                side_effect=mocked_requests,
            )
        )
    ],
    "IntelX_Phonebook": [
        mock_connections(
            patch(
                "requests.Session.post",
                side_effect=lambda *args, **kwargs: MockResponse({"id": 1}, 200),
            )
        ),
        mock_connections(
            patch(
                "requests.Session.get",
                side_effect=lambda *args, **kwargs: MockResponse(
                    {"selectors": []}, 200
                ),
            )
        ),
    ],
    "MISPFIRST": [
        mock_connections(patch("pymisp.PyMISP", side_effect=mocked_requests_noop))
    ],
    "GoogleWebRisk": [
        mock_connections(
            patch(
                "api_app.analyzers_manager.observable_analyzers.dns."
                "dns_malicious_detectors.google_webrisk.WebRiskServiceClient"
            )
        )
    ],
}
