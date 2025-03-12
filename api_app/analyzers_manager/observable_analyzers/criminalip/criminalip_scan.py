import logging
import time

import requests
from requests import HTTPError

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from tests.mock_utils import MockUpResponse, if_mock_connections, patch

from .criminalip_base import CriminalIpBase

logger = logging.getLogger(__name__)


class CriminalIpScan(classes.ObservableAnalyzer, CriminalIpBase):
    status_endpoint = "/v1/domain/status/"
    scan_endpoint = "/v1/domain/scan/"
    private_scan_endpoint = "/v1/domain/scan/private"
    report_endpoint = "/v1/domain/report/"
    timeout: int = 20

    def update(self):
        pass

    def run(self):
        HEADER = self.getHeaders()
        poll_distance = 5  # seconds
        resp = requests.post(
            url=f"{self.url}{self.scan_endpoint}",
            headers=HEADER,
            data={"query": self.observable_name},
        )
        resp.raise_for_status()
        resp = resp.json()
        if resp.get("status", None) not in [None, 200]:
            raise HTTPError(resp.get("message", ""))
        logger.info(
            f"response from CriminalIp_scan for {self.observable_name} -> {resp}"
        )

        id = resp["scan_id"]
        while True:
            resp = requests.get(
                url=f"{self.url}{self.status_endpoint}{id}", headers=HEADER
            )
            resp.raise_for_status()

            scan_percent = resp.json()["data"]["scan_percentage"]
            if scan_percent == 100:
                break
            time.sleep(poll_distance)
            self.timeout -= poll_distance
            if self.timeout <= 0:
                raise AnalyzerRunException(
                    f"Timeout with scan percentage: {scan_percent}"
                )
        resp = requests.get(url=f"{self.url}{self.report_endpoint}{id}", headers=HEADER)
        resp.raise_for_status()
        resp = resp.json()
        logger.info(
            f"response from CriminalIp_scan for {self.observable_name} -> {resp}"
        )
        return resp

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.get",
                    side_effect=[
                        MockUpResponse(
                            {
                                "status": 200,
                                "message": "api success",
                                "data": {"scan_percentage": 100},
                            },
                            200,
                        ),
                        # flake8: noqa
                        MockUpResponse(
                            {
                                "status": 200,
                                "message": "api success",
                                "data": {
                                    "certificates": [
                                        {
                                            "certificate_life": "2 Months",
                                            "issuer": "WR2",
                                            "protocol": "TLS 1.3",
                                            "subject": "*.apis.google.com",
                                            "valid_from": "2024-06-24 07:42:56",
                                            "valid_to": "2024-09-16 07:42:55",
                                        },
                                        {
                                            "certificate_life": "2 Months",
                                            "issuer": "WR2",
                                            "protocol": "TLS 1.3",
                                            "subject": "upload.video.google.com",
                                            "valid_from": "2024-06-24 07:40:53",
                                            "valid_to": "2024-09-16 07:40:52",
                                        },
                                        {
                                            "certificate_life": "2 Months",
                                            "issuer": "WR2",
                                            "protocol": "TLS 1.3",
                                            "subject": "*.gstatic.com",
                                            "valid_from": "2024-06-24 07:40:48",
                                            "valid_to": "2024-09-16 07:40:47",
                                        },
                                        {
                                            "certificate_life": "2 Months",
                                            "issuer": "WR2",
                                            "protocol": "TLS 1.3",
                                            "subject": "www.google.com",
                                            "valid_from": "2024-06-24 07:42:34",
                                            "valid_to": "2024-09-16 07:42:33",
                                        },
                                    ],
                                    "classification": {
                                        "dga_score": 0.011,
                                        "domain_type": [
                                            {"name": "top_rank", "type": "general"},
                                            {"name": "liste_bu", "type": "general"},
                                            {
                                                "name": "searchengines",
                                                "type": "general",
                                            },
                                            {
                                                "name": "certificate_site_type",
                                                "type": "general",
                                            },
                                        ],
                                        "google_safe_browsing": [],
                                    },
                                    "connected_domain_subdomain": [
                                        {
                                            "main_domain": {"domain": "google.com"},
                                            "subdomains": [
                                                {"domain": "www.google.com"},
                                                {"domain": "apis.google.com"},
                                            ],
                                        },
                                        {
                                            "main_domain": {"domain": "gstatic.com"},
                                            "subdomains": [
                                                {"domain": "www.gstatic.com"}
                                            ],
                                        },
                                        {
                                            "main_domain": {"domain": "googleapis.com"},
                                            "subdomains": [
                                                {"domain": "ogads-pa.googleapis.com"}
                                            ],
                                        },
                                    ],
                                    "connected_ip": [
                                        {"ip": "172.217.25.164", "score": "safe"},
                                        {"ip": "142.250.206.227", "score": "safe"},
                                        {"ip": "142.250.76.138", "score": "safe"},
                                        {"ip": "172.217.25.174", "score": "safe"},
                                    ],
                                    "connected_ip_info": [
                                        {
                                            "as_name": "GOOGLE",
                                            "asn": "15169",
                                            "cnt": 23,
                                            "country": "US",
                                            "domain_list": [
                                                {"domain": "www.google.com"}
                                            ],
                                            "ip": "172.217.25.164",
                                            "redirect_cnt": 0,
                                            "score": "Safe",
                                        },
                                        {
                                            "as_name": "GOOGLE",
                                            "asn": "15169",
                                            "cnt": 3,
                                            "country": "US",
                                            "domain_list": [
                                                {"domain": "www.gstatic.com"}
                                            ],
                                            "ip": "142.250.206.227",
                                            "redirect_cnt": 0,
                                            "score": "Safe",
                                        },
                                        {
                                            "as_name": "GOOGLE",
                                            "asn": "15169",
                                            "cnt": 2,
                                            "country": "US",
                                            "domain_list": [
                                                {"domain": "ogads-pa.googleapis.com"}
                                            ],
                                            "ip": "142.250.76.138",
                                            "redirect_cnt": 0,
                                            "score": "Safe",
                                        },
                                        {
                                            "as_name": "GOOGLE",
                                            "asn": "15169",
                                            "cnt": 1,
                                            "country": "US",
                                            "domain_list": [
                                                {"domain": "apis.google.com"}
                                            ],
                                            "ip": "172.217.25.174",
                                            "redirect_cnt": 0,
                                            "score": "Safe",
                                        },
                                    ],
                                    "cookies": [],
                                    "detected_program": {
                                        "program_data_in_html_source": [],
                                        "program_data_with_access": [],
                                    },
                                    "dns_record": {
                                        "dns_record_type_a": {
                                            "ipv4": [
                                                {
                                                    "ip": "172.217.25.174",
                                                    "score": "safe",
                                                }
                                            ],
                                            "ipv6": [
                                                {
                                                    "ip": "2404:6800:400a:813::200e",
                                                    "score": "low",
                                                }
                                            ],
                                        },
                                        "dns_record_type_cname": [],
                                        "dns_record_type_mx": [["smtp.google.com"]],
                                        "dns_record_type_ns": [
                                            "ns1.google.com.",
                                            "ns2.google.com.",
                                            "ns4.google.com.",
                                            "ns3.google.com.",
                                        ],
                                        "dns_record_type_ptr": [],
                                        "dns_record_type_soa": [],
                                    },
                                    "file_exposure": {
                                        "apache_status": False,
                                        "docker_registry": False,
                                        "ds_store": False,
                                        "firebase": False,
                                        "git_config": False,
                                        "json_config": False,
                                        "phpinfo": False,
                                        "vscode_sftp_json": False,
                                        "wordpress": False,
                                    },
                                    "frames": [
                                        {
                                            "frame_id": "66D65CE114D5E693B22399A4950C10F7",
                                            "transfer_cnt": 18,
                                            "url": "https://www.google.com/?gws_rd=ssl",
                                        }
                                    ],
                                    "html_page_link_domains": [
                                        {
                                            "domain": "www.google.com",
                                            "mapped_ips": [
                                                {
                                                    "as_name": "GOOGLE",
                                                    "country": "US",
                                                    "ip": "172.217.25.164",
                                                    "score": "safe",
                                                }
                                            ],
                                            "nslookup_time": "2024-07-24 07:14:23",
                                        },
                                        {
                                            "domain": "about.google",
                                            "mapped_ips": [
                                                {
                                                    "as_name": "GOOGLE",
                                                    "country": "US",
                                                    "ip": "216.239.32.29",
                                                    "score": "safe",
                                                }
                                            ],
                                            "nslookup_time": "2024-07-24 07:14:23",
                                        },
                                        {
                                            "domain": "store.google.com",
                                            "mapped_ips": [
                                                {
                                                    "as_name": "GOOGLE",
                                                    "country": "US",
                                                    "ip": "142.250.206.206",
                                                    "score": "low",
                                                }
                                            ],
                                            "nslookup_time": "2024-07-24 07:14:23",
                                        },
                                        {
                                            "domain": "accounts.google.com",
                                            "mapped_ips": [
                                                {
                                                    "as_name": "GOOGLE",
                                                    "country": "US",
                                                    "ip": "142.251.170.84",
                                                    "score": "safe",
                                                }
                                            ],
                                            "nslookup_time": "2024-07-24 07:14:23",
                                        },
                                        {
                                            "domain": "www.google.co.kr",
                                            "mapped_ips": [
                                                {
                                                    "as_name": "GOOGLE",
                                                    "country": "US",
                                                    "ip": "142.250.76.131",
                                                    "score": "safe",
                                                }
                                            ],
                                            "nslookup_time": "2024-07-24 07:14:23",
                                        },
                                        {
                                            "domain": "mail.google.com",
                                            "mapped_ips": [
                                                {
                                                    "as_name": "GOOGLE",
                                                    "country": "US",
                                                    "ip": "142.250.206.229",
                                                    "score": "low",
                                                }
                                            ],
                                            "nslookup_time": "2024-07-24 07:14:23",
                                        },
                                        {
                                            "domain": "google.com",
                                            "mapped_ips": [
                                                {
                                                    "as_name": "GOOGLE",
                                                    "country": "US",
                                                    "ip": "172.217.25.174",
                                                    "score": "safe",
                                                }
                                            ],
                                            "nslookup_time": "2024-07-24 07:14:23",
                                        },
                                        {
                                            "domain": "policies.google.com",
                                            "mapped_ips": [
                                                {
                                                    "as_name": "GOOGLE",
                                                    "country": "US",
                                                    "ip": "142.250.207.110",
                                                    "score": "safe",
                                                }
                                            ],
                                            "nslookup_time": "2024-07-24 07:14:23",
                                        },
                                        {
                                            "domain": "support.google.com",
                                            "mapped_ips": [
                                                {
                                                    "as_name": "GOOGLE",
                                                    "country": "US",
                                                    "ip": "142.250.206.206",
                                                    "score": "low",
                                                }
                                            ],
                                            "nslookup_time": "2024-07-24 07:14:23",
                                        },
                                    ],
                                    "javascript_variables": [
                                        {
                                            "variable_name": "0",
                                            "variable_type": "object",
                                        },
                                        {
                                            "variable_name": "google",
                                            "variable_type": "object",
                                        },
                                        {
                                            "variable_name": "gws_wizbind",
                                            "variable_type": "object",
                                        },
                                        {
                                            "variable_name": "_",
                                            "variable_type": "object",
                                        },
                                        {
                                            "variable_name": "_DumpException",
                                            "variable_type": "function",
                                        },
                                        {
                                            "variable_name": "_s",
                                            "variable_type": "object",
                                        },
                                        {
                                            "variable_name": "_qs",
                                            "variable_type": "object",
                                        },
                                        {
                                            "variable_name": "_xjs_toggles",
                                            "variable_type": "object",
                                        },
                                        {
                                            "variable_name": "_F_toggles",
                                            "variable_type": "object",
                                        },
                                        {
                                            "variable_name": "_F_installCss",
                                            "variable_type": "function",
                                        },
                                        {
                                            "variable_name": "_F_jsUrl",
                                            "variable_type": "string",
                                        },
                                        {
                                            "variable_name": "gbar_",
                                            "variable_type": "object",
                                        },
                                        {
                                            "variable_name": "gbar",
                                            "variable_type": "object",
                                        },
                                        {
                                            "variable_name": "__PVT",
                                            "variable_type": "string",
                                        },
                                        {
                                            "variable_name": "gapi",
                                            "variable_type": "object",
                                        },
                                        {
                                            "variable_name": "___jsl",
                                            "variable_type": "object",
                                        },
                                        {
                                            "variable_name": "sbmlhf",
                                            "variable_type": "function",
                                        },
                                        {
                                            "variable_name": "w",
                                            "variable_type": "function",
                                        },
                                        {
                                            "variable_name": "W_jd",
                                            "variable_type": "object",
                                        },
                                        {
                                            "variable_name": "WIZ_global_data",
                                            "variable_type": "object",
                                        },
                                        {
                                            "variable_name": "IJ_values",
                                            "variable_type": "object",
                                        },
                                        {
                                            "variable_name": "jsl",
                                            "variable_type": "object",
                                        },
                                        {
                                            "variable_name": "_hd",
                                            "variable_type": "object",
                                        },
                                        {
                                            "variable_name": "closure_lm_257926",
                                            "variable_type": "object",
                                        },
                                        {
                                            "variable_name": "lnk",
                                            "variable_type": "object",
                                        },
                                        {
                                            "variable_name": "silk",
                                            "variable_type": "object",
                                        },
                                        {
                                            "variable_name": "_F_installCssProto",
                                            "variable_type": "function",
                                        },
                                        {
                                            "variable_name": "wiz_progress",
                                            "variable_type": "function",
                                        },
                                        {
                                            "variable_name": "closure_uid_639501253",
                                            "variable_type": "number",
                                        },
                                        {
                                            "variable_name": "closure_lm_260040",
                                            "variable_type": "object",
                                        },
                                        {
                                            "variable_name": "userfeedback",
                                            "variable_type": "object",
                                        },
                                        {
                                            "variable_name": "osapi",
                                            "variable_type": "object",
                                        },
                                        {
                                            "variable_name": "gadgets",
                                            "variable_type": "object",
                                        },
                                        {
                                            "variable_name": "shindig",
                                            "variable_type": "object",
                                        },
                                        {
                                            "variable_name": "googleapis",
                                            "variable_type": "object",
                                        },
                                    ],
                                    "links": [
                                        {
                                            "title": "Google 정보",
                                            "url": "https://about.google/?fg=1&utm_source=google-KR&utm_medium=referral&utm_campaign=hp-header",
                                        },
                                        {
                                            "title": "스토어",
                                            "url": "https://store.google.com/KR?utm_source=hp_header&utm_medium=google_ooo&utm_campaign=GS100042&hl=ko-KR",
                                        },
                                        {
                                            "title": "Gmail",
                                            "url": "https://mail.google.com/mail/&ogbl",
                                        },
                                        {
                                            "title": "이미지",
                                            "url": "https://www.google.com/imghp?hl=ko&ogbl",
                                        },
                                        {
                                            "title": "",
                                            "url": "https://www.google.co.kr/intl/ko/about/products",
                                        },
                                        {
                                            "title": "로그인",
                                            "url": "https://accounts.google.com/ServiceLogin?hl=ko&passive=True&continue=https://www.google.com/%3Fgws_rd%3Dssl&ec=GAZAmgQ",
                                        },
                                        {
                                            "title": "English",
                                            "url": "https://www.google.com/setprefs?sig=0_2n_e0Ut_MPaTbcl_o32YThy-tmc%3D&hl=en&source=homepage&sa=X&ved=0ahUKEwjzr_eKicCHAxVaiK8BHXDXNoEQ2ZgBCBc",
                                        },
                                        {
                                            "title": "광고",
                                            "url": "https://www.google.com/intl/ko_kr/ads/?subid=ww-ww-et-g-awa-a-g_hpafoot1_1!o2&utm_source=google.com&utm_medium=referral&utm_campaign=google_hpafooter&fg=1",
                                        },
                                        {
                                            "title": "비즈니스",
                                            "url": "https://www.google.com/services/?subid=ww-ww-et-g-awa-a-g_hpbfoot1_1!o2&utm_source=google.com&utm_medium=referral&utm_campaign=google_hpbfooter&fg=1",
                                        },
                                        {
                                            "title": "검색의 원리",
                                            "url": "https://google.com/search/howsearchworks/?fg=1",
                                        },
                                        {
                                            "title": "개인정보처리방침",
                                            "url": "https://policies.google.com/privacy?hl=ko&fg=1",
                                        },
                                        {
                                            "title": "약관",
                                            "url": "https://policies.google.com/terms?hl=ko&fg=1",
                                        },
                                        {
                                            "title": "검색 설정",
                                            "url": "https://www.google.com/preferences?hl=ko&fg=1",
                                        },
                                        {
                                            "title": "검색 도움말",
                                            "url": "https://support.google.com/websearch/?p=ws_results_help&hl=ko&fg=1",
                                        },
                                    ],
                                    "main_certificate": {
                                        "enddate": "2024-09-16 06:35:43",
                                        "issuer": "WR2",
                                        "signed_algorithm": "sha256WithRSAEncryption",
                                        "startdate": "2024-06-24 06:35:44",
                                        "subject": "",
                                    },
                                    "main_domain_info": {
                                        "changed_url": "https://www.google.com/?gws_rd=ssl",
                                        "dns_ip_asn": "",
                                        "domain_created": "1997-09-15",
                                        "domain_registrar": "MarkMonitor Inc.",
                                        "domain_score": {
                                            "score": "low",
                                            "score_num": 1.0,
                                            "score_percentage": 40,
                                        },
                                        "favicon": [],
                                        "inserted_url": "http://google.com",
                                        "jarm": "27d40d40d29d40d1dc42d43d00041d4689ee210389f4f6b4b5b1b93f92252d",
                                        "main_domain": "google.com",
                                        "title": "Google",
                                    },
                                    "mapped_ip": [
                                        {
                                            "as_name": "GOOGLE",
                                            "country": "us",
                                            "ip": "172.217.25.174",
                                            "score": "safe",
                                        }
                                    ],
                                    "network_logs": {
                                        "abuse_record": {"critical": 0, "dangerous": 0},
                                        "data": [
                                            {
                                                "as_name": "GOOGLE",
                                                "as_number": "15169",
                                                "country": "us",
                                                "data_size": "1.12 KB",
                                                "frame_id": "66D65CE114D5E693B22399A4950C10F7",
                                                "ip_port": "172.217.25.164:443",
                                                "mime_type": "text/html",
                                                "protocol": "h2",
                                                "request": "GET",
                                                "score": "safe",
                                                "time": "0.01 ms",
                                                "transfer_size": "59.04 KB",
                                                "type": "Document",
                                                "url": "https://www.google.com/?gws_rd=ssl",
                                            },
                                            {
                                                "as_name": "GOOGLE",
                                                "as_number": "15169",
                                                "country": "us",
                                                "data_size": "419 B",
                                                "frame_id": "66D65CE114D5E693B22399A4950C10F7",
                                                "ip_port": "172.217.25.164:443",
                                                "mime_type": "text/css",
                                                "protocol": "h2",
                                                "request": "GET",
                                                "score": "safe",
                                                "time": "0.01 ms",
                                                "transfer_size": "1.21 KB",
                                                "type": "Stylesheet",
                                                "url": "https://www.google.com/xjs/_/ss/k=xjs.hd.xpNscl4L4EM.L.B1.O/am=AEwBAAAAAAAAGAAAAAAAAAAAAAAAAAAACAAABAAAAAAAoAAgkACAAMAGBAAAAEAAgAAAAAAAACgAAAAABgAAAAIASAAgACAgAAAAAAAhgACAABCgCCABIAiiCAAAAAEAEAFgwDAAgQoABgEAAAAIIAAAAACAGwEIEADQRwCAAACBAEAggA4QAAAACAABAAAMYIAAAAAAAAAAwAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAQAFAAAAAAAAAAAAAAAAAAAACA/d=1/ed=1/br=1/rs=ACT90oEU4alHvocxkfsKg5_yo22FOP0sWw/m=cdos,hsm,jsa,mb4ZUb,d,csi,cEt90b,SNUn3,qddgKe,sTsDMc,dtl0hd,eHDfl",
                                            },
                                            {
                                                "as_name": "GOOGLE",
                                                "as_number": "15169",
                                                "country": "us",
                                                "data_size": "81 B",
                                                "frame_id": "66D65CE114D5E693B22399A4950C10F7",
                                                "ip_port": "172.217.25.164:443",
                                                "mime_type": "text/javascript",
                                                "protocol": "h2",
                                                "request": "GET",
                                                "score": "safe",
                                                "time": "0.01 ms",
                                                "transfer_size": "339.87 KB",
                                                "type": "Script",
                                                "url": "https://www.google.com/xjs/_/js/k=xjs.hd.en.THugEEezihI.O/am=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAhAAUAACAAgAAAAAAAAAAAABAgCAAgCgAAAgABwCIgACAQAAAAIEgAI8yAQAgAEwAAAAACAAAIAgAgAAAAAEAAAEAAAAAAAoAAAAAAAAAAAAAADCAAAIAAAAAAAAAAAAAAAAAgA4AAAAAAgCAIAAMYIAAEIAAAAAA9AAgOAAGKQgAAAAAAAAAAAAAAAQgQTAXElAQQAAAAAAAAAAAAAAAAACkpBMLGw/d=1/ed=1/dg=3/br=1/rs=ACT90oFmJvZNdCtpEcsB5F0K4PatjnRKig/ee=ALeJib:B8gLwd;AfeaP:TkrAjf;BMxAGc:E5bFse;BgS6mb:fidj5d;BjwMce:cXX2Wb;CxXAWb:YyRLvc;DM55c:imLrKe;DULqB:RKfG5c;Dkk6ge:wJqrrd;DpcR3d:zL72xf;EABSZ:MXZt9d;ESrPQc:mNTJvc;EVNhjf:pw70Gc;EmZ2Bf:zr1jrb;EnlcNd:WeHg4;Erl4fe:FloWmf,FloWmf;F9mqte:UoRcbe;Fmv9Nc:O1Tzwc;G0KhTb:LIaoZ;G6wU6e:hezEbd;GleZL:J1A7Od;HMDDWe:G8QUdb;HoYVKb:PkDN7e;HqeXPd:cmbnH;IBADCc:RYquRb;IZrNqe:P8ha2c;IoGlCf:b5lhvb;IsdWVc:qzxzOb;JXS8fb:Qj0suc;JbMT3:M25sS;JsbNhc:Xd8iUd;KOxcK:OZqGte;KQzWid:ZMKkN;KcokUb:KiuZBf;KpRAue:Tia57b;LBgRLc:SdcwHb,XVMNvd;LEikZe:byfTOb,lsjVmc;LXA8b:q7OdKd;LsNahb:ucGLNb;Me32dd:MEeYgc;NPKaK:SdcwHb;NSEoX:lazG7b;Np8Qkd:Dpx6qc;Nyt6ic:jn2sGd;OgagBe:cNTe0;Oj465e:KG2eXe,KG2eXe;OohIYe:mpEAQb;Pjplud:EEDORb,PoEs9b;Q1Ow7b:x5CSu;Q6C5kf:pfdZCe;QGR0gd:Mlhmy;R2kc8b:ALJqWb;R4IIIb:QWfeKf;R9Ulx:CR7Ufe;RDNBlf:zPRCJb;SLtqO:Kh1xYe;SMDL4c:fTfGO,fTfGO;SNUn3:ZwDk9d,x8cHvb;ShpF6e:N0pvGc;SzQQ3e:dNhofb;TxfV6d:YORN0b;U96pRd:FsR04;UBKJZ:LGDJGb;UDrY1c:eps46d;UVmjEd:EesRsb;UyG7Kb:wQd0G;V2HTTe:RolTY;VGRfx:VFqbr;VN6jIc:ddQyuf;VOcgDe:YquhTb;VsAqSb:PGf2Re;VxQ32b:k0XsBb;WCEKNd:I46Hvd;WDGyFe:jcVOxd;Wfmdue:g3MJlb;XUezZ:sa7lqb;YV5bee:IvPZ6d;YkQtAf:rx8ur;ZMvdv:PHFPjb;ZSH6tc:QAvyLe;ZWEUA:afR4Cf;a56pNe:JEfCwb;aAJE9c:WHW6Ef;aCJ9tf:qKftvc;aZ61od:arTwJ;af0EJf:ghinId;bDXwRe:UsyOtc;bcPXSc:gSZLJb;cEt90b:ws9Tlc;cFTWae:gT8qnd;coJ8e:KvoW8;dIoSBb:ZgGg9b;dLlj2:Qqt3Gf;daB6be:lMxGPd;dtl0hd:lLQWFe;eBAeSb:Ck63tb;eBZ5Nd:VruDBd;eHDfl:ofjVkb;eO3lse:nFClrf;euOXY:OZjbQ;g8nkx:U4MzKc;gaub4:TN6bMe;gtVSi:ekUOYd;h3MYod:cEt90b;hK67qb:QWEO5b;heHB1:sFczq;hjRo6e:F62sG;hsLsYc:Vl118;iFQyKf:QIhFr,vfuNJf;imqimf:jKGL2e;io8t5d:sgY6Zb;jY0zg:Q6tNgc;k2Qxcb:XY51pe;kCQyJ:ueyPK;kMFpHd:OTA3Ae;kbAm9d:MkHyGd;lkq0A:JyBE3e;nAFL3:NTMZac,s39S4;nJw4Gd:dPFZH;oGtAuc:sOXFj;oSUNyd:fTfGO,fTfGO;oUlnpc:RagDlc;okUaUd:wItadb;pKJiXd:VCenhc;pNsl2d:j9Yuyc;pXdRYb:JKoKVe;pj82le:mg5CW;qZx2Fc:j0xrE;qaS3gd:yiLg6e;qavrXe:zQzcXe;qddgKe:d7YSfd,x4FYXe;rQSrae:C6D5Fc;sP4Vbe:VwDzFe;sTsDMc:kHVSUb;sZmdvc:rdGEfc;tH4IIe:Ymry6;tosKvd:ZCqP3;trZL0b:qY8PFe;uY49fb:COQbmf;uuQkY:u2V3ud;vGrMZ:lPJJ0c;vfVwPd:lcrkwe;w3bZCb:ZPGaIb;w4rSdf:XKiZ9;w9w86d:dt4g2b;wQlYve:aLUfP;wR5FRb:O1Gjze,TtcOte;wV5Pjc:L8KGxe;whEZac:F4AmNb;xBbsrc:NEW1Qc;ysNiMc:CpIBjd;yxTchf:KUM7Z;z97YGf:oug9te;zOsCQe:Ko78Df;zaIgPb:Qtpxbd/m=cdos,hsm,jsa,mb4ZUb,d,csi,cEt90b,SNUn3,qddgKe,sTsDMc,dtl0hd,eHDfl",
                                            },
                                            {
                                                "as_name": "GOOGLE",
                                                "as_number": "15169",
                                                "country": "us",
                                                "data_size": "117 B",
                                                "frame_id": "66D65CE114D5E693B22399A4950C10F7",
                                                "ip_port": "172.217.25.164:443",
                                                "mime_type": "image/png",
                                                "protocol": "h2",
                                                "request": "GET",
                                                "score": "safe",
                                                "time": "0.01 ms",
                                                "transfer_size": "5.97 KB",
                                                "type": "Image",
                                                "url": "https://www.google.com/images/branding/googlelogo/1x/googlelogo_color_272x92dp.png",
                                            },
                                            {
                                                "as_name": "GOOGLE",
                                                "as_number": "15169",
                                                "country": "us",
                                                "data_size": "300 B",
                                                "frame_id": "66D65CE114D5E693B22399A4950C10F7",
                                                "ip_port": "172.217.25.164:443",
                                                "mime_type": "image/png",
                                                "protocol": "h2",
                                                "request": "GET",
                                                "score": "safe",
                                                "time": "0.01 ms",
                                                "transfer_size": "258 B",
                                                "type": "Image",
                                                "url": "https://www.google.com/tia/tia.png",
                                            },
                                            {
                                                "as_name": "GOOGLE",
                                                "as_number": "15169",
                                                "country": "us",
                                                "data_size": "504 B",
                                                "frame_id": "66D65CE114D5E693B22399A4950C10F7",
                                                "ip_port": "142.250.206.227:443",
                                                "mime_type": "image/png",
                                                "protocol": "h2",
                                                "request": "GET",
                                                "score": "safe",
                                                "time": "0.01 ms",
                                                "transfer_size": "151 B",
                                                "type": "Image",
                                                "url": "https://www.gstatic.com/inputtools/images/tia.png",
                                            },
                                            {
                                                "as_name": "GOOGLE",
                                                "as_number": "15169",
                                                "country": "us",
                                                "data_size": "84 B",
                                                "frame_id": "66D65CE114D5E693B22399A4950C10F7",
                                                "ip_port": "172.217.25.164:443",
                                                "mime_type": "image/webp",
                                                "protocol": "h2",
                                                "request": "GET",
                                                "score": "safe",
                                                "time": "0.01 ms",
                                                "transfer_size": "660 B",
                                                "type": "Image",
                                                "url": "https://www.google.com/images/searchbox/desktop_searchbox_sprites318_hr.webp",
                                            },
                                            {
                                                "as_name": "GOOGLE",
                                                "as_number": "15169",
                                                "country": "us",
                                                "data_size": "357 B",
                                                "frame_id": "66D65CE114D5E693B22399A4950C10F7",
                                                "ip_port": "142.250.206.227:443",
                                                "mime_type": "text/javascript",
                                                "protocol": "h2",
                                                "request": "GET",
                                                "score": "safe",
                                                "time": "0.01 ms",
                                                "transfer_size": "80.64 KB",
                                                "type": "Script",
                                                "url": "https://www.gstatic.com/og/_/js/k=og.qtm.en_US.nk_8sj4-PqI.2019.O/rt=j/m=qabr,q_d,qcwid,qapid,qald,qads,q_dg/exm=qaaw,qadd,qaid,qein,qhaw,qhba,qhbr,qhch,qhga,qhid,qhin/d=1/ed=1/rs=AA2YrTskXiTqHlipJ-mR0xUZEKmb0KeqCw",
                                            },
                                            {
                                                "as_name": "GOOGLE",
                                                "as_number": "15169",
                                                "country": "us",
                                                "data_size": "125 B",
                                                "frame_id": "66D65CE114D5E693B22399A4950C10F7",
                                                "ip_port": "142.250.206.227:443",
                                                "mime_type": "text/css",
                                                "protocol": "h2",
                                                "request": "GET",
                                                "score": "safe",
                                                "time": "0.01 ms",
                                                "transfer_size": "2.24 KB",
                                                "type": "Stylesheet",
                                                "url": "https://www.gstatic.com/og/_/ss/k=og.qtm.3qrU4w2FVtU.L.W.O/m=qcwid,d_b_gm3,d_wi_gm3,d_lo_gm3/excm=qaaw,qadd,qaid,qein,qhaw,qhba,qhbr,qhch,qhga,qhid,qhin/d=1/ed=1/ct=zgms/rs=AA2YrTvDcvshkEefRPXsUqQTCGr4E1xK4A",
                                            },
                                            {
                                                "as_name": "GOOGLE",
                                                "as_number": "15169",
                                                "country": "us",
                                                "data_size": "220 B",
                                                "frame_id": "66D65CE114D5E693B22399A4950C10F7",
                                                "ip_port": "172.217.25.164:443",
                                                "mime_type": "text/html",
                                                "protocol": "h2",
                                                "request": "POST",
                                                "score": "safe",
                                                "time": "0.01 ms",
                                                "transfer_size": "0 B",
                                                "type": "Ping",
                                                "url": "https://www.google.com/gen_204?s=webhp&t=aft&atyp=csi&ei=TyihZrPMOdqQvr0P8K7biQg&rt=wsrt.465,aft.309,hst.44,prt.309&imn=11&ima=0&imad=0&imac=1&wh=1080&aft=1&aftp=-1&opi=89978449",
                                            },
                                            {
                                                "as_name": "GOOGLE",
                                                "as_number": "15169",
                                                "country": "us",
                                                "data_size": "204 B",
                                                "frame_id": "66D65CE114D5E693B22399A4950C10F7",
                                                "ip_port": "172.217.25.164:443",
                                                "mime_type": "text/html",
                                                "protocol": "h2",
                                                "request": "POST",
                                                "score": "safe",
                                                "time": "0.01 ms",
                                                "transfer_size": "0 B",
                                                "type": "Ping",
                                                "url": "https://www.google.com/gen_204?atyp=csi&ei=TyihZrPMOdqQvr0P8K7biQg&s=webhp&t=all&imn=11&ima=0&imad=0&imac=1&wh=1080&aft=1&aftp=-1&adh=&ime=1&imeae=0&imeap=0&imex=1&imeh=1&imeha=0&imehb=0&imea=0&imeb=0&imel=0&imed=0&imeeb=0&scp=0&cb=59044&ucb=205932&mem=ujhs.10,tjhs.10,jhsl.2190,dm.4&net=dl.10000,ect.4g,rtt.0&hp=&sys=hc.2&p=bs.True&rt=hst.44,prt.309,aft.309,aftqf.449,xjses.528,xjsee.838,xjs.839,lcp.293,fcp.273,wsrt.465,cst.96,dnst.0,rqst.189,rspt.67,sslt.78,rqstt.343,unt.243,cstt.245,dit.956&zx=1721837648887&opi=89978449",
                                            },
                                            {
                                                "as_name": "GOOGLE",
                                                "as_number": "15169",
                                                "country": "us",
                                                "data_size": "281 B",
                                                "frame_id": "66D65CE114D5E693B22399A4950C10F7",
                                                "ip_port": "172.217.25.164:443",
                                                "mime_type": "application/json",
                                                "protocol": "h2",
                                                "request": "GET",
                                                "score": "safe",
                                                "time": "0.01 ms",
                                                "transfer_size": "0 B",
                                                "type": "XHR",
                                                "url": "https://www.google.com/complete/search?q&cp=0&client=gws-wiz&xssi=t&gs_pcrt=2&hl=ko&authuser=0&psi=TyihZrPMOdqQvr0P8K7biQg.1721837648935&dpr=1&nolsbt=1",
                                            },
                                            {
                                                "as_name": "GOOGLE",
                                                "as_number": "15169",
                                                "country": "us",
                                                "data_size": "87 B",
                                                "frame_id": "66D65CE114D5E693B22399A4950C10F7",
                                                "ip_port": "172.217.25.164:443",
                                                "mime_type": "text/javascript",
                                                "protocol": "h2",
                                                "request": "GET",
                                                "score": "safe",
                                                "time": "0.01 ms",
                                                "transfer_size": "149.96 KB",
                                                "type": "Script",
                                                "url": "https://www.google.com/xjs/_/js/k=xjs.hd.en.THugEEezihI.O/ck=xjs.hd.xpNscl4L4EM.L.B1.O/am=AEwBAAAAAAAAGAAAAAAAAAAAAAAAAAAACAAABAAAAAAApAA0kACAAsAGBAAAAEAAgABAgCAAgCgAAAgABwCIgAKASAAgAKEgAI8yAQAhgEyAABCgCCABIAiiiAAAAAEAEAFgwDAAgQoABgEAAAAIIAAAADCAGwMIEADQRwCAAACBAEAggA4QAAAACgCBIAAMYIAAEIAAAAAA9AAgOAAGKQgAAAAAAAAAAAAAAAQgQTAXElAQQAAAAAAAAAAAAAAAAACkpBMLGw/d=0/dg=0/br=1/ujg=1/rs=ACT90oG-r6R0wy9pi2mMf8V18VUuEU5IGQ/m=sb_wiz,aa,abd,sy112,sysf,sysb,sy111,syt2,sys9,syt3,syt4,sysw,sysv,sysx,syss,syst,sysp,syso,sysk,syfb,sysn,sysl,sysm,sysj,sysz,sysg,sysc,sysd,syrb,syr0,syqz,syqy,sysr,sy110,sywj,sytb,sytc,syta,async,pHXghd,sf,sy175,sy178,sy487,sonic,TxCJfd,sy48b,qzxzOb,IsdWVc,sy1c1,sy18c,sy188,syqx,syqv,syqw,syqu,syqt,sy46s,sy2cl,sy1fc,sy11r,syqq,syqo,syep,syc5,sybk,sybj,sybh,spch,syre,syrd,rtH1bd,sy19i,sy152,sy14p,sy19h,sy11w,sy19g,SMquOb,sy8l,syg2,syg1,syg0,syg3,syg9,syg7,syg6,syg5,syfz,syb0,syav,syaz,syay,syau,syax,syah,syao,sycd,sybz,syas,sy9v,sy9x,syc0,sybn,sybd,syba,sybb,syag,syb6,syb4,syb5,syb7,sya3,syb8,sybo,syfj,syfy,syfv,syfx,syfr,sy9t,sya2,sya0,sy9q,sya1,syfu,sycl,syfs,syfp,syfo,syfm,sy84,sy81,sy83,syfl,syfq,syfk,syfe,syfg,syfd,syfc,sy87,uxMpU,syf7,sycj,syaa,syab,sya9,syac,sya8,syce,sycf,syb9,syca,sycb,syc6,syby,sybw,sybx,syb3,syar,syaf,sy9r,syc9,syad,sycc,sych,syc4,sy91,sy90,sy8z,Mlhmy,QGR0gd,aurFic,sy9a,fKUV3e,OTA3Ae,sy8m,OmgaI,EEDORb,PoEs9b,Pjplud,sy8w,sy8r,COQbmf,uY49fb,sy7y,sy7w,sy7x,sy7v,sy7u,byfTOb,lsjVmc,LEikZe,kWgXee,U0aPgd,ovKuLd,sgY6Zb,io8t5d,KG2eXe,Oj465e,sy19m,sy19j,syw4,syru,d5EhJe,sy1a3,fCxEDd,syuf,sy1a2,sy1a1,sy1a0,sy19z,sy19v,sy19t,sy19q,sy19r,sy19u,sy16r,sy16i,syue,syzq,syzp,T1HOxc,sy19s,sy19p,zx30Y,sy1a5,sy1a4,sy19x,Wo3n8,sytn,loL8vb,sytr,sytq,sytp,ms4mZb,sypo,B2qlPe,sytz,NzU6V,syww,sywv,zGLm3b,syvn,syvo,syvf,DhPYme,MpJwZc,UUJqVe,sy7r,sOXFj,sy7q,s39S4,oGtAuc,NTMZac,nAFL3,sy8j,sy8i,q0xTif,y05UD,sy127,sy18z,sy18m,sy18v,sy122,sy18t,sy18s,syzo,sy18k,sy13q,syzn,syzm,syzl,sy18r,sy13i,sy18g,sy13n,sy18q,sy18l,sy18h,sy13o,sy13p,sy18u,sy18p,sy11t,sy18o,syje,syjf,sy18n,sy18w,sy18a,sy18i,sy189,sy18f,sy18b,sy14g,sy18j,sy185,sy13s,sy13t,syzt,syzu,epYOx?xjs=s3",
                                            },
                                            {
                                                "as_name": "GOOGLE",
                                                "as_number": "15169",
                                                "country": "us",
                                                "data_size": "88 B",
                                                "frame_id": "66D65CE114D5E693B22399A4950C10F7",
                                                "ip_port": "172.217.25.164:443",
                                                "mime_type": "text/javascript",
                                                "protocol": "h2",
                                                "request": "GET",
                                                "score": "safe",
                                                "time": "0.01 ms",
                                                "transfer_size": "1.42 KB",
                                                "type": "Fetch",
                                                "url": "https://www.google.com/xjs/_/js/md=2/k=xjs.hd.en.THugEEezihI.O/am=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAhAAUAACAAgAAAAAAAAAAAABAgCAAgCgAAAgABwCIgACAQAAAAIEgAI8yAQAgAEwAAAAACAAAIAgAgAAAAAEAAAEAAAAAAAoAAAAAAAAAAAAAADCAAAIAAAAAAAAAAAAAAAAAgA4AAAAAAgCAIAAMYIAAEIAAAAAA9AAgOAAGKQgAAAAAAAAAAAAAAAQgQTAXElAQQAAAAAAAAAAAAAAAAACkpBMLGw/rs=ACT90oFmJvZNdCtpEcsB5F0K4PatjnRKig",
                                            },
                                            {
                                                "as_name": "GOOGLE",
                                                "as_number": "15169",
                                                "country": "us",
                                                "data_size": "294 B",
                                                "frame_id": "66D65CE114D5E693B22399A4950C10F7",
                                                "ip_port": "172.217.25.164:443",
                                                "mime_type": "text/html",
                                                "protocol": "h2",
                                                "request": "GET",
                                                "score": "safe",
                                                "time": "0.01 ms",
                                                "transfer_size": "0 B",
                                                "type": "Image",
                                                "url": "https://www.google.com/client_204?atyp=i&biw=1920&bih=1080&ei=TyihZrPMOdqQvr0P8K7biQg&opi=89978449",
                                            },
                                            {
                                                "as_name": "GOOGLE",
                                                "as_number": "15169",
                                                "country": "us",
                                                "data_size": "385 B",
                                                "frame_id": "",
                                                "ip_port": "142.250.76.138:443",
                                                "mime_type": "text/html",
                                                "protocol": "h2",
                                                "request": "OPTIONS",
                                                "score": "safe",
                                                "time": "0.01 ms",
                                                "transfer_size": "0 B",
                                                "type": "Other",
                                                "url": "https://ogads-pa.googleapis.com/$rpc/google.internal.onegoogle.asyncdata.v1.AsyncDataService/GetAsyncData",
                                            },
                                            {
                                                "as_name": "GOOGLE",
                                                "as_number": "15169",
                                                "country": "us",
                                                "data_size": "194 B",
                                                "frame_id": "66D65CE114D5E693B22399A4950C10F7",
                                                "ip_port": "142.250.76.138:443",
                                                "mime_type": "application/json+protobuf",
                                                "protocol": "h2",
                                                "request": "POST",
                                                "score": "safe",
                                                "time": "0.01 ms",
                                                "transfer_size": "30 B",
                                                "type": "XHR",
                                                "url": "https://ogads-pa.googleapis.com/$rpc/google.internal.onegoogle.asyncdata.v1.AsyncDataService/GetAsyncData",
                                            },
                                            {
                                                "as_name": "GOOGLE",
                                                "as_number": "15169",
                                                "country": "us",
                                                "data_size": "580 B",
                                                "frame_id": "66D65CE114D5E693B22399A4950C10F7",
                                                "ip_port": "172.217.25.174:443",
                                                "mime_type": "text/javascript",
                                                "protocol": "h2",
                                                "request": "GET",
                                                "score": "safe",
                                                "time": "0.01 ms",
                                                "transfer_size": "42.23 KB",
                                                "type": "Script",
                                                "url": "https://apis.google.com/_/scs/abc-static/_/js/k=gapi.gapi.en.MGCxJbnW_Xw.O/m=gapi_iframes,googleapis_client/rt=j/sv=1/d=1/ed=1/am=AAAg/rs=AHpOoo9xa4htLEVH9xe6c4ToUehtTaLWvA/cb=gapi.loaded_0",
                                            },
                                            {
                                                "as_name": "GOOGLE",
                                                "as_number": "15169",
                                                "country": "us",
                                                "data_size": "80 B",
                                                "frame_id": "66D65CE114D5E693B22399A4950C10F7",
                                                "ip_port": "172.217.25.164:443",
                                                "mime_type": "text/css",
                                                "protocol": "h2",
                                                "request": "GET",
                                                "score": "safe",
                                                "time": "0.01 ms",
                                                "transfer_size": "371 B",
                                                "type": "Fetch",
                                                "url": "https://www.google.com/xjs/_/ss/k=xjs.hd.xpNscl4L4EM.L.B1.O/am=AEwBAAAAAAAAGAAAAAAAAAAAAAAAAAAACAAABAAAAAAAoAAgkACAAMAGBAAAAEAAgAAAAAAAACgAAAAABgAAAAIASAAgACAgAAAAAAAhgACAABCgCCABIAiiCAAAAAEAEAFgwDAAgQoABgEAAAAIIAAAAACAGwEIEADQRwCAAACBAEAggA4QAAAACAABAAAMYIAAAAAAAAAAwAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAQAFAAAAAAAAAAAAAAAAAAAACA/d=0/br=1/rs=ACT90oEU4alHvocxkfsKg5_yo22FOP0sWw/m=syj9,sykh?xjs=s4",
                                            },
                                            {
                                                "as_name": "GOOGLE",
                                                "as_number": "15169",
                                                "country": "us",
                                                "data_size": "79 B",
                                                "frame_id": "66D65CE114D5E693B22399A4950C10F7",
                                                "ip_port": "172.217.25.164:443",
                                                "mime_type": "text/javascript",
                                                "protocol": "h2",
                                                "request": "GET",
                                                "score": "safe",
                                                "time": "0.01 ms",
                                                "transfer_size": "7.89 KB",
                                                "type": "Script",
                                                "url": "https://www.google.com/xjs/_/js/k=xjs.hd.en.THugEEezihI.O/am=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAhAAUAACAAgAAAAAAAAAAAABAgCAAgCgAAAgABwCIgACAQAAAAIEgAI8yAQAgAEwAAAAACAAAIAgAgAAAAAEAAAEAAAAAAAoAAAAAAAAAAAAAADCAAAIAAAAAAAAAAAAAAAAAgA4AAAAAAgCAIAAMYIAAEIAAAAAA9AAgOAAGKQgAAAAAAAAAAAAAAAQgQTAXElAQQAAAAAAAAAAAAAAAAACkpBMLGw/d=0/dg=0/br=1/rs=ACT90oFmJvZNdCtpEcsB5F0K4PatjnRKig/m=sy1b9,P10Owf,sy19y,sy19w,syqg,gSZvdb,sywd,sywc,WlNQGd,sywq,sywo,nabPbb,syql,syqi,syqh,syqf,DPreE,syw7,syw5,syj9,sykh,CnSW2d,kQvlef,sywp,fXO0xe?xjs=s4",
                                            },
                                            {
                                                "as_name": "GOOGLE",
                                                "as_number": "15169",
                                                "country": "us",
                                                "data_size": "206 B",
                                                "frame_id": "66D65CE114D5E693B22399A4950C10F7",
                                                "ip_port": "172.217.25.164:443",
                                                "mime_type": "text/html",
                                                "protocol": "h2",
                                                "request": "POST",
                                                "score": "safe",
                                                "time": "0.01 ms",
                                                "transfer_size": "0 B",
                                                "type": "Ping",
                                                "url": "https://www.google.com/gen_204?atyp=csi&ei=TyihZrPMOdqQvr0P8K7biQg&s=promo&rt=hpbas.1181&zx=1721837649221&opi=89978449",
                                            },
                                            {
                                                "as_name": "GOOGLE",
                                                "as_number": "15169",
                                                "country": "us",
                                                "data_size": "205 B",
                                                "frame_id": "66D65CE114D5E693B22399A4950C10F7",
                                                "ip_port": "172.217.25.164:443",
                                                "mime_type": "text/html",
                                                "protocol": "h2",
                                                "request": "POST",
                                                "score": "safe",
                                                "time": "0.01 ms",
                                                "transfer_size": "0 B",
                                                "type": "Ping",
                                                "url": "https://www.google.com/gen_204?atyp=i&ei=TyihZrPMOdqQvr0P8K7biQg&dt19=2&prm23=0&zx=1721837649233&opi=89978449",
                                            },
                                            {
                                                "as_name": "GOOGLE",
                                                "as_number": "15169",
                                                "country": "us",
                                                "data_size": "436 B",
                                                "frame_id": "66D65CE114D5E693B22399A4950C10F7",
                                                "ip_port": "172.217.25.164:443",
                                                "mime_type": "text/html",
                                                "protocol": "h2",
                                                "request": "GET",
                                                "score": "safe",
                                                "time": "0.01 ms",
                                                "transfer_size": "0 B",
                                                "type": "XHR",
                                                "url": "https://www.google.com/client_204?cs=1&opi=89978449",
                                            },
                                            {
                                                "as_name": "GOOGLE",
                                                "as_number": "15169",
                                                "country": "us",
                                                "data_size": "194 B",
                                                "frame_id": "66D65CE114D5E693B22399A4950C10F7",
                                                "ip_port": "172.217.25.164:443",
                                                "mime_type": "text/plain",
                                                "protocol": "h2",
                                                "request": "GET",
                                                "score": "safe",
                                                "time": "0.01 ms",
                                                "transfer_size": "0 B",
                                                "type": "XHR",
                                                "url": "https://www.google.com/async/hpba?vet=10ahUKEwjzr_eKicCHAxVaiK8BHXDXNoEQj-0KCBU..i&ei=TyihZrPMOdqQvr0P8K7biQg&opi=89978449&yv=3&cs=0&async=isImageHp:False,eventId:TyihZrPMOdqQvr0P8K7biQg,endpoint:overlay,stick:,_basejs:%2Fxjs%2F_%2Fjs%2Fk%3Dxjs.hd.en.THugEEezihI.O%2Fam%3DAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAhAAUAACAAgAAAAAAAAAAAABAgCAAgCgAAAgABwCIgACAQAAAAIEgAI8yAQAgAEwAAAAACAAAIAgAgAAAAAEAAAEAAAAAAAoAAAAAAAAAAAAAADCAAAIAAAAAAAAAAAAAAAAAgA4AAAAAAgCAIAAMYIAAEIAAAAAA9AAgOAAGKQgAAAAAAAAAAAAAAAQgQTAXElAQQAAAAAAAAAAAAAAAAACkpBMLGw%2Fdg%3D0%2Fbr%3D1%2Frs%3DACT90oFmJvZNdCtpEcsB5F0K4PatjnRKig,_basecss:%2Fxjs%2F_%2Fss%2Fk%3Dxjs.hd.xpNscl4L4EM.L.B1.O%2Fam%3DAEwBAAAAAAAAGAAAAAAAAAAAAAAAAAAACAAABAAAAAAAoAAgkACAAMAGBAAAAEAAgAAAAAAAACgAAAAABgAAAAIASAAgACAgAAAAAAAhgACAABCgCCABIAiiCAAAAAEAEAFgwDAAgQoABgEAAAAIIAAAAACAGwEIEADQRwCAAACBAEAggA4QAAAACAABAAAMYIAAAAAAAAAAwAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAQAFAAAAAAAAAAAAAAAAAAAACA%2Fbr%3D1%2Frs%3DACT90oEU4alHvocxkfsKg5_yo22FOP0sWw,_basecomb:%2Fxjs%2F_%2Fjs%2Fk%3Dxjs.hd.en.THugEEezihI.O%2Fck%3Dxjs.hd.xpNscl4L4EM.L.B1.O%2Fam%3DAEwBAAAAAAAAGAAAAAAAAAAAAAAAAAAACAAABAAAAAAApAA0kACAAsAGBAAAAEAAgABAgCAAgCgAAAgABwCIgAKASAAgAKEgAI8yAQAhgEyAABCgCCABIAiiiAAAAAEAEAFgwDAAgQoABgEAAAAIIAAAADCAGwMIEADQRwCAAACBAEAggA4QAAAACgCBIAAMYIAAEIAAAAAA9AAgOAAGKQgAAAAAAAAAAAAAAAQgQTAXElAQQAAAAAAAAAAAAAAAAACkpBMLGw%2Fd%3D1%2Fed%3D1%2Fdg%3D0%2Fbr%3D1%2Fujg%3D1%2Frs%3DACT90oG-r6R0wy9pi2mMf8V18VUuEU5IGQ,_fmt:prog,_id:a3JU5b",
                                            },
                                            {
                                                "as_name": "GOOGLE",
                                                "as_number": "15169",
                                                "country": "us",
                                                "data_size": "208 B",
                                                "frame_id": "66D65CE114D5E693B22399A4950C10F7",
                                                "ip_port": "172.217.25.164:443",
                                                "mime_type": "text/html",
                                                "protocol": "h2",
                                                "request": "GET",
                                                "score": "safe",
                                                "time": "0.01 ms",
                                                "transfer_size": "0 B",
                                                "type": "Image",
                                                "url": "https://www.google.com/gen_204?atyp=i&ct=psnt&cad=&nt=navigate&ei=TyihZrPMOdqQvr0P8K7biQg&zx=1721837649373&opi=89978449",
                                            },
                                            {
                                                "as_name": "GOOGLE",
                                                "as_number": "15169",
                                                "country": "us",
                                                "data_size": "207 B",
                                                "frame_id": "66D65CE114D5E693B22399A4950C10F7",
                                                "ip_port": "172.217.25.164:443",
                                                "mime_type": "text/html",
                                                "protocol": "h2",
                                                "request": "POST",
                                                "score": "safe",
                                                "time": "0.01 ms",
                                                "transfer_size": "0 B",
                                                "type": "Ping",
                                                "url": "https://www.google.com/gen_204?atyp=csi&ei=USihZqazEc6Vvr0P_7mXKQ&s=async&astyp=hpba&ima=0&imn=0&mem=ujhs.10,tjhs.10,jhsl.2190,dm.4&hp=&rt=ttfb.156,st.157,bs.27,aaft.161,acrt.170,art.171&zx=1721837649401&opi=89978449",
                                            },
                                            {
                                                "as_name": "GOOGLE",
                                                "as_number": "15169",
                                                "country": "us",
                                                "data_size": "208 B",
                                                "frame_id": "66D65CE114D5E693B22399A4950C10F7",
                                                "ip_port": "172.217.25.164:443",
                                                "mime_type": "text/html",
                                                "protocol": "h2",
                                                "request": "POST",
                                                "score": "safe",
                                                "time": "0.01 ms",
                                                "transfer_size": "0 B",
                                                "type": "Ping",
                                                "url": "https://www.google.com/gen_204?atyp=csi&ei=TyihZrPMOdqQvr0P8K7biQg&s=promo&rt=hpbas.1181,hpbarr.182&zx=1721837649404&opi=89978449",
                                            },
                                            {
                                                "as_name": "GOOGLE",
                                                "as_number": "15169",
                                                "country": "us",
                                                "data_size": "56 B",
                                                "frame_id": "66D65CE114D5E693B22399A4950C10F7",
                                                "ip_port": "172.217.25.164:443",
                                                "mime_type": "text/javascript",
                                                "protocol": "h2",
                                                "request": "GET",
                                                "score": "safe",
                                                "time": "0.01 ms",
                                                "transfer_size": "630 B",
                                                "type": "Script",
                                                "url": "https://www.google.com/xjs/_/js/k=xjs.hd.en.THugEEezihI.O/am=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAhAAUAACAAgAAAAAAAAAAAABAgCAAgCgAAAgABwCIgACAQAAAAIEgAI8yAQAgAEwAAAAACAAAIAgAgAAAAAEAAAEAAAAAAAoAAAAAAAAAAAAAADCAAAIAAAAAAAAAAAAAAAAAgA4AAAAAAgCAIAAMYIAAEIAAAAAA9AAgOAAGKQgAAAAAAAAAAAAAAAQgQTAXElAQQAAAAAAAAAAAAAAAAACkpBMLGw/d=0/dg=0/br=1/rs=ACT90oFmJvZNdCtpEcsB5F0K4PatjnRKig/m=syfa,aLUfP?xjs=s4",
                                            },
                                            {
                                                "as_name": "GOOGLE",
                                                "as_number": "15169",
                                                "country": "us",
                                                "data_size": "57 B",
                                                "frame_id": "66D65CE114D5E693B22399A4950C10F7",
                                                "ip_port": "172.217.25.164:443",
                                                "mime_type": "text/javascript",
                                                "protocol": "h2",
                                                "request": "GET",
                                                "score": "safe",
                                                "time": "0.01 ms",
                                                "transfer_size": "808 B",
                                                "type": "Script",
                                                "url": "https://www.google.com/xjs/_/js/k=xjs.hd.en.THugEEezihI.O/am=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAhAAUAACAAgAAAAAAAAAAAABAgCAAgCgAAAgABwCIgACAQAAAAIEgAI8yAQAgAEwAAAAACAAAIAgAgAAAAAEAAAEAAAAAAAoAAAAAAAAAAAAAADCAAAIAAAAAAAAAAAAAAAAAgA4AAAAAAgCAIAAMYIAAEIAAAAAA9AAgOAAGKQgAAAAAAAAAAAAAAAQgQTAXElAQQAAAAAAAAAAAAAAAAACkpBMLGw/d=0/dg=0/br=1/rs=ACT90oFmJvZNdCtpEcsB5F0K4PatjnRKig/m=kMFpHd,sy8x,bm51tf?xjs=s4",
                                            },
                                        ],
                                    },
                                    "page_networking_info": {
                                        "connected_countries": "US",
                                        "cookies": 3,
                                        "encryption": "sha256WithRSAEncryption",
                                        "https_percent": 100.0,
                                        "tls_certificate": "TLS 1.3",
                                        "transaction_count": 29,
                                        "transfer_traffic": "693.38 KB",
                                    },
                                    "page_redirections": [
                                        [
                                            {
                                                "as_name": "GOOGLE",
                                                "country_code": "US",
                                                "status": 301,
                                                "url": "http://google.com/",
                                            },
                                            {
                                                "as_name": "GOOGLE",
                                                "country_code": "US",
                                                "status": 302,
                                                "url": "http://www.google.com/",
                                            },
                                            {
                                                "as_name": "GOOGLE",
                                                "country_code": "US",
                                                "status": 200,
                                                "url": "https://www.google.com/?gws_rd=ssl",
                                            },
                                        ]
                                    ],
                                    "report_time": "2024-07-24 16:14:23",
                                    "screenshots": [
                                        "https://cip-web-screenshot-new.s3.us-west-1.amazonaws.com/domain/2024/7/24_16_14_google.com.png"
                                    ],
                                    "security_headers": [],
                                    "ssl": False,
                                    "ssl_detail": {
                                        "forward_secrecy": {
                                            "elliptic_curves_offered": "",
                                            "finite_field_group": "",
                                            "forward_secrecy": "",
                                            "forward_secrecy_ciphers": "",
                                        },
                                        "headers": {
                                            "cookies": "",
                                            "hsts": "",
                                            "security_headers": {
                                                "cache_control": "",
                                                "pragma": "",
                                                "referrer_policy": "",
                                                "x_frame_options": "",
                                                "x_xss_protection": "",
                                            },
                                        },
                                        "protocols": {
                                            "deprecated_ssl_protocol_versions": {
                                                "sslv2": "",
                                                "sslv3": "",
                                            },
                                            "tls_warning": "",
                                        },
                                        "server_defaults": {
                                            "chain_of_trust": [],
                                            "dns_caa_record": [],
                                            "server_key_size": [],
                                            "tls_session_resumption": {
                                                "id": "",
                                                "tickets": "",
                                            },
                                        },
                                        "vulnerable": {
                                            "beast": {"tls1": "", "value": ""},
                                            "breach_attacks": "",
                                            "ccs_injection": "",
                                            "client_initiated_ssl_renegotiation": "",
                                            "crime_tls": "",
                                            "drown": "",
                                            "freak": "",
                                            "heartbleed": "",
                                            "logjam": "",
                                            "lucky13": "",
                                            "poodle": "",
                                            "robot": "",
                                            "ssl_rc4": "",
                                            "ssl_renegotiation": "",
                                            "sweet32": "",
                                            "ticketbleed": "",
                                            "tls_fallback_scsv": "",
                                            "winshock": "",
                                        },
                                    },
                                    "subdomains": [
                                        {"subdomain_name": "design.google.com"},
                                        {"subdomain_name": "ns2.google.com"},
                                        {"subdomain_name": "videos.google.com"},
                                        {"subdomain_name": "wifi.google.com"},
                                        {"subdomain_name": "events.google.com"},
                                        {"subdomain_name": "desktop.google.com"},
                                        {"subdomain_name": "games.google.com"},
                                        {"subdomain_name": "help.google.com"},
                                        {"subdomain_name": "ns.google.com"},
                                        {"subdomain_name": "uploads.google.com"},
                                        {"subdomain_name": "webmaster.google.com"},
                                        {"subdomain_name": "ww.google.com"},
                                        {"subdomain_name": "labs.google.com"},
                                        {"subdomain_name": "survey.google.com"},
                                        {"subdomain_name": "photo.google.com"},
                                        {"subdomain_name": "edu.google.com"},
                                        {"subdomain_name": "services.google.com"},
                                        {"subdomain_name": "music.google.com"},
                                        {"subdomain_name": "mars.google.com"},
                                        {"subdomain_name": "sandbox.google.com"},
                                        {"subdomain_name": "contacts.google.com"},
                                        {"subdomain_name": "image.google.com"},
                                        {"subdomain_name": "tools.google.com"},
                                        {"subdomain_name": "calendar.google.com"},
                                        {"subdomain_name": "directory.google.com"},
                                        {"subdomain_name": "ns1.google.com"},
                                        {"subdomain_name": "chat.google.com"},
                                        {"subdomain_name": "tv.google.com"},
                                        {"subdomain_name": "smtp.google.com"},
                                        {"subdomain_name": "shopping.google.com"},
                                        {"subdomain_name": "email.google.com"},
                                        {"subdomain_name": "accounts.google.com"},
                                        {"subdomain_name": "archive.google.com"},
                                        {"subdomain_name": "billing.google.com"},
                                        {"subdomain_name": "careers.google.com"},
                                        {"subdomain_name": "postmaster.google.com"},
                                        {"subdomain_name": "forms.google.com"},
                                        {"subdomain_name": "time.google.com"},
                                        {"subdomain_name": "map.google.com"},
                                        {"subdomain_name": "domains.google.com"},
                                        {"subdomain_name": "doc.google.com"},
                                        {"subdomain_name": "m.google.com"},
                                        {"subdomain_name": "web.google.com"},
                                        {"subdomain_name": "security.google.com"},
                                        {"subdomain_name": "dl.google.com"},
                                        {"subdomain_name": "ipv4.google.com"},
                                        {"subdomain_name": "finance.google.com"},
                                        {"subdomain_name": "ns4.google.com"},
                                        {"subdomain_name": "home.google.com"},
                                        {"subdomain_name": "maps.google.com"},
                                        {"subdomain_name": "research.google.com"},
                                        {"subdomain_name": "payments.google.com"},
                                        {"subdomain_name": "travel.google.com"},
                                        {"subdomain_name": "wap.google.com"},
                                        {"subdomain_name": "sms.google.com"},
                                        {"subdomain_name": "groups.google.com"},
                                        {"subdomain_name": "ns3.google.com"},
                                        {"subdomain_name": "files.google.com"},
                                        {"subdomain_name": "gmail.google.com"},
                                        {"subdomain_name": "download.google.com"},
                                        {"subdomain_name": "work.google.com"},
                                        {"subdomain_name": "w.google.com"},
                                        {"subdomain_name": "local.google.com"},
                                        {"subdomain_name": "feeds.google.com"},
                                        {"subdomain_name": "www5.google.com"},
                                        {"subdomain_name": "mail.google.com"},
                                        {"subdomain_name": "www6.google.com"},
                                        {"subdomain_name": "api.google.com"},
                                        {"subdomain_name": "apps.google.com"},
                                        {"subdomain_name": "search.google.com"},
                                        {"subdomain_name": "sites.google.com"},
                                        {"subdomain_name": "store.google.com"},
                                        {"subdomain_name": "jobs.google.com"},
                                        {"subdomain_name": "classroom.google.com"},
                                        {"subdomain_name": "business.google.com"},
                                        {"subdomain_name": "pay.google.com"},
                                        {"subdomain_name": "d.google.com"},
                                        {"subdomain_name": "docs.google.com"},
                                        {"subdomain_name": "support.google.com"},
                                        {"subdomain_name": "corp.google.com"},
                                        {"subdomain_name": "images.google.com"},
                                        {"subdomain_name": "catalog.google.com"},
                                        {"subdomain_name": "orion.google.com"},
                                        {"subdomain_name": "mobile.google.com"},
                                        {"subdomain_name": "health.google.com"},
                                        {"subdomain_name": "vpn.google.com"},
                                        {"subdomain_name": "dns.google.com"},
                                        {"subdomain_name": "catalogue.google.com"},
                                        {"subdomain_name": "blog.google.com"},
                                        {"subdomain_name": "upload.google.com"},
                                        {"subdomain_name": "www4.google.com"},
                                        {"subdomain_name": "video.google.com"},
                                        {"subdomain_name": "www.google.com"},
                                        {"subdomain_name": "admin.google.com"},
                                        {"subdomain_name": "photos.google.com"},
                                        {"subdomain_name": "foto.google.com"},
                                        {"subdomain_name": "ads.google.com"},
                                        {"subdomain_name": "analytics.google.com"},
                                        {"subdomain_name": "lp.google.com"},
                                        {"subdomain_name": "downloads.google.com"},
                                        {"subdomain_name": "developers.google.com"},
                                        {"subdomain_name": "partners.google.com"},
                                        {"subdomain_name": "cloud.google.com"},
                                        {"subdomain_name": "news.google.com"},
                                        {"subdomain_name": "on.google.com"},
                                        {"subdomain_name": "meet.google.com"},
                                        {"subdomain_name": "ldap.google.com"},
                                        {"subdomain_name": "id.google.com"},
                                    ],
                                    "summary": {
                                        "abuse_record": {"critical": 0, "dangerous": 0},
                                        "connect_to_ip_directly": 0,
                                        "cred_input": "Safe",
                                        "dga_score": 0.011,
                                        "diff_domain_favicon": "Safe",
                                        "fake_domain": False,
                                        "fake_https_url": False,
                                        "fake_ssl": {"category": "", "invalid": False},
                                        "hidden_element": 0,
                                        "hidden_iframe": 0,
                                        "iframe": 0,
                                        "js_obfuscated": 8,
                                        "list_of_countries": ["US"],
                                        "mail_server": True,
                                        "mitm_attack": False,
                                        "newborn_domain": "",
                                        "overlong_domain": False,
                                        "phishing_record": 1,
                                        "punycode": False,
                                        "redirection_diff_asn": 0,
                                        "redirection_diff_country": 0,
                                        "redirection_diff_domain": 0,
                                        "redirection_onclick": "Normal",
                                        "sfh": "Safe",
                                        "spf1": "Safe",
                                        "suspicious_cookie": False,
                                        "suspicious_element": 0,
                                        "suspicious_file": 0,
                                        "symbol_url": False,
                                        "url_phishing_prob": 1.15,
                                        "web_traffic": "1",
                                    },
                                    "technologies": [
                                        {
                                            "categories": ["Web servers"],
                                            "name": "Google Web Server",
                                            "version": None,
                                            "vulner": [],
                                        }
                                    ],
                                },
                            },
                            200,
                        ),
                    ],
                ),
                patch(
                    "requests.post",
                    side_effect=[
                        MockUpResponse(
                            {
                                "status": 200,
                                "message": "api success",
                                "data": {
                                    "query": "http://google.com",
                                    "scan_id": 14341560,
                                },
                            },
                            200,
                        ),
                        MockUpResponse(
                            {
                                "meta": {"asn": "5577", "period": 5},
                                "response": {
                                    "asn_history": [
                                        ["2019-11-10", 0.00036458333333333335],
                                        ["2019-11-11", 0.00036168981481481485],
                                        ["2019-11-12", 0.0003761574074074074],
                                        ["2019-11-13", 0.0003530092592592593],
                                        ["2019-11-14", 0.0003559027777777778],
                                    ]
                                },
                            },
                            200,
                        ),
                    ],
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
