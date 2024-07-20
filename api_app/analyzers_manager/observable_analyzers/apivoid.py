# flake8: noqa
# done for the mocked respose,
# everything else is linted and tested
import requests

from api_app.analyzers_manager import classes
from tests.mock_utils import MockUpResponse, if_mock_connections, patch


class ApiVoidAnalyzer(classes.ObservableAnalyzer):
    url = "https://endpoint.apivoid.com"
    _api_key: str = None

    def update(self):
        pass

    def run(self):
        if self.observable_classification == self.ObservableTypes.DOMAIN.value:
            url = (
                self.url
                + f"""/domainbl/v1/pay-as-you-go/
                ?key={self._api_key}
                &host={self.observable_name}"""
            )
        elif self.observable_classification == self.ObservableTypes.IP.value:
            url = (
                self.url
                + f"""/iprep/v1/pay-as-you-go/
                ?key={self._api_key}
                &ip={self.observable_name}"""
            )
        elif self.observable_classification == self.ObservableTypes.URL.value:
            url = (
                self.url
                + f"""/urlrep/v1/pay-as-you-go/
                ?key={self._api_key}
                &url={self.observable_name}"""
            )
        r = requests.get(url)
        r.raise_for_status()
        return r.json()

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.get",
                    return_value=MockUpResponse(
                        {
                            {
                                "data": {
                                    "report": {
                                        "ip": "2.57.122.0",
                                        "version": "v4",
                                        "blacklists": {
                                            "engines": {
                                                "0": {
                                                    "engine": "0spam",
                                                    "detected": False,
                                                    "reference": "https:\/\/0spam.org\/",
                                                    "elapsed": "0.09",
                                                },
                                                "12": {
                                                    "engine": "APEWS-L2",
                                                    "detected": False,
                                                    "reference": "http:\/\/www.apews.org\/",
                                                    "elapsed": "0.00",
                                                },
                                                "13": {
                                                    "engine": "AZORult Tracker",
                                                    "detected": False,
                                                    "reference": "https:\/\/azorult-tracker.net\/",
                                                    "elapsed": "0.00",
                                                },
                                                "10": {
                                                    "engine": "Anti-Attacks BL",
                                                    "detected": True,
                                                    "reference": "https:\/\/www.anti-attacks.com\/",
                                                    "elapsed": "0.00",
                                                },
                                                "11": {
                                                    "engine": "AntiSpam_by_CleanTalk",
                                                    "detected": False,
                                                    "reference": "https:\/\/cleantalk.org\/",
                                                    "elapsed": "0.00",
                                                },
                                                "14": {
                                                    "engine": "Backscatterer",
                                                    "detected": False,
                                                    "reference": "https:\/\/www.backscatterer.org\/",
                                                    "elapsed": "0.00",
                                                },
                                                "1": {
                                                    "engine": "Barracuda_Reputation_BL",
                                                    "detected": False,
                                                    "reference": "https:\/\/barracudacentral.org\/lookups",
                                                    "elapsed": "0.07",
                                                },
                                                "16": {
                                                    "engine": "BlockList_de",
                                                    "detected": False,
                                                    "reference": "https:\/\/www.blocklist.de\/",
                                                    "elapsed": "0.00",
                                                },
                                                "2": {
                                                    "engine": "BlockedServersRBL",
                                                    "detected": False,
                                                    "reference": "https:\/\/www.blockedservers.com\/",
                                                    "elapsed": "0.37",
                                                },
                                                "15": {
                                                    "engine": "Blocking_rocks",
                                                    "detected": False,
                                                    "reference": "https:\/\/blocking.rocks\/",
                                                    "elapsed": "0.00",
                                                },
                                                "17": {
                                                    "engine": "Blocklist.net.ua",
                                                    "detected": False,
                                                    "reference": "https:\/\/blocklist.net.ua\/",
                                                    "elapsed": "0.00",
                                                },
                                                "18": {
                                                    "engine": "Botscout (Last Caught)",
                                                    "detected": False,
                                                    "reference": "https:\/\/botscout.com\/",
                                                    "elapsed": "0.00",
                                                },
                                                "19": {
                                                    "engine": "Botvrij.eu",
                                                    "detected": False,
                                                    "reference": "https:\/\/botvrij.eu\/",
                                                    "elapsed": "0.00",
                                                },
                                                "20": {
                                                    "engine": "Brute Force Blocker",
                                                    "detected": False,
                                                    "reference": "https:\/\/danger.rulez.sk\/index.php\/bruteforceblocker\/",
                                                    "elapsed": "0.00",
                                                },
                                                "21": {
                                                    "engine": "C-APT-ure",
                                                    "detected": False,
                                                    "reference": "https:\/\/c-apt-ure.blogspot.com\/",
                                                    "elapsed": "0.00",
                                                },
                                                "23": {
                                                    "engine": "CI Army List",
                                                    "detected": False,
                                                    "reference": "https:\/\/cinsscore.com\/#list",
                                                    "elapsed": "0.00",
                                                },
                                                "24": {
                                                    "engine": "CRDF",
                                                    "detected": True,
                                                    "reference": "https:\/\/threatcenter.crdf.fr\/check.html",
                                                    "elapsed": "0.00",
                                                },
                                                "26": {
                                                    "engine": "CSpace Hostings IP BL",
                                                    "detected": True,
                                                    "reference": "https:\/\/cspacehostings.com\/",
                                                    "elapsed": "0.00",
                                                },
                                                "22": {
                                                    "engine": "Charles Haley",
                                                    "detected": False,
                                                    "reference": "https:\/\/charles.the-haleys.org\/",
                                                    "elapsed": "0.00",
                                                },
                                                "25": {
                                                    "engine": "CruzIT Blocklist",
                                                    "detected": False,
                                                    "reference": "https:\/\/www.cruzit.com\/",
                                                    "elapsed": "0.00",
                                                },
                                                "27": {
                                                    "engine": "Cybercrime-tracker.net",
                                                    "detected": False,
                                                    "reference": "https:\/\/cybercrime-tracker.net\/",
                                                    "elapsed": "0.00",
                                                },
                                                "28": {
                                                    "engine": "Darklist.de",
                                                    "detected": False,
                                                    "reference": "https:\/\/www.darklist.de\/",
                                                    "elapsed": "0.00",
                                                },
                                                "29": {
                                                    "engine": "Dataplane.org",
                                                    "detected": False,
                                                    "reference": "https:\/\/dataplane.org\/",
                                                    "elapsed": "0.00",
                                                },
                                                "3": {
                                                    "engine": "EFnet_RBL",
                                                    "detected": False,
                                                    "reference": "https:\/\/rbl.efnetrbl.org\/multicheck.php",
                                                    "elapsed": "0.19",
                                                },
                                                "30": {
                                                    "engine": "ELLIO IP Feed",
                                                    "detected": False,
                                                    "reference": "https:\/\/ellio.tech\/",
                                                    "elapsed": "0.00",
                                                },
                                                "31": {
                                                    "engine": "Etnetera BL",
                                                    "detected": False,
                                                    "reference": "https:\/\/security.etnetera.cz\/",
                                                    "elapsed": "0.00",
                                                },
                                                "33": {
                                                    "engine": "FSpamList",
                                                    "detected": False,
                                                    "reference": "https:\/\/fspamlist.com\/",
                                                    "elapsed": "0.00",
                                                },
                                                "32": {
                                                    "engine": "Feodo Tracker",
                                                    "detected": False,
                                                    "reference": "https:\/\/feodotracker.abuse.ch\/",
                                                    "elapsed": "0.00",
                                                },
                                                "34": {
                                                    "engine": "GPF DNS Block List",
                                                    "detected": False,
                                                    "reference": "https:\/\/www.gpf-comics.com\/dnsbl\/export.php",
                                                    "elapsed": "0.00",
                                                },
                                                "35": {
                                                    "engine": "GreenSnow Blocklist",
                                                    "detected": False,
                                                    "reference": "https:\/\/greensnow.co\/",
                                                    "elapsed": "0.00",
                                                },
                                                "36": {
                                                    "engine": "HoneyDB",
                                                    "detected": False,
                                                    "reference": "https:\/\/honeydb.io\/",
                                                    "elapsed": "0.00",
                                                },
                                                "4": {
                                                    "engine": "IBM_Cobion",
                                                    "detected": False,
                                                    "reference": "https:\/\/filterdb.iss.net\/dnsblinfo\/",
                                                    "elapsed": "0.10",
                                                },
                                                "38": {
                                                    "engine": "IPSpamList",
                                                    "detected": False,
                                                    "reference": "https:\/\/www.ipspamlist.com\/ip-lookup\/",
                                                    "elapsed": "0.00",
                                                },
                                                "39": {
                                                    "engine": "IPsum",
                                                    "detected": False,
                                                    "reference": "https:\/\/github.com\/stamparm\/ipsum",
                                                    "elapsed": "0.00",
                                                },
                                                "40": {
                                                    "engine": "ISX.fr DNSBL",
                                                    "detected": False,
                                                    "reference": "https:\/\/bl.isx.fr\/",
                                                    "elapsed": "0.00",
                                                },
                                                "37": {
                                                    "engine": "InterServer IP List",
                                                    "detected": False,
                                                    "reference": "https:\/\/sigs.interserver.net\/",
                                                    "elapsed": "0.00",
                                                },
                                                "41": {
                                                    "engine": "JamesBrine IP List",
                                                    "detected": False,
                                                    "reference": "https:\/\/jamesbrine.com.au\/",
                                                    "elapsed": "0.00",
                                                },
                                                "5": {
                                                    "engine": "JustSpam_org",
                                                    "detected": False,
                                                    "reference": "http:\/\/www.justspam.org\/",
                                                    "elapsed": "0.14",
                                                },
                                                "6": {
                                                    "engine": "Known Scanning Service",
                                                    "detected": False,
                                                    "reference": "https:\/\/www.novirusthanks.org\/",
                                                    "elapsed": "0.00",
                                                },
                                                "42": {
                                                    "engine": "LAPPS Grid Blacklist",
                                                    "detected": False,
                                                    "reference": "https:\/\/lappsgrid.org\/",
                                                    "elapsed": "0.00",
                                                },
                                                "43": {
                                                    "engine": "Liquid Binary",
                                                    "detected": False,
                                                    "reference": "https:\/\/liquidbinary.com\/",
                                                    "elapsed": "0.00",
                                                },
                                                "44": {
                                                    "engine": "M4lwhere Intel",
                                                    "detected": False,
                                                    "reference": "https:\/\/m4lwhere.org\/",
                                                    "elapsed": "0.00",
                                                },
                                                "45": {
                                                    "engine": "Mark Smith Blocked IPs",
                                                    "detected": False,
                                                    "reference": "https:\/\/www.marksmith.it\/",
                                                    "elapsed": "0.00",
                                                },
                                                "46": {
                                                    "engine": "Mirai Tracker",
                                                    "detected": False,
                                                    "reference": "https:\/\/mirai.security.gives\/index.php",
                                                    "elapsed": "0.00",
                                                },
                                                "47": {
                                                    "engine": "Myip.ms Blacklist",
                                                    "detected": False,
                                                    "reference": "https:\/\/myip.ms\/browse\/blacklist",
                                                    "elapsed": "0.00",
                                                },
                                                "48": {
                                                    "engine": "NEU SSH Black list",
                                                    "detected": False,
                                                    "reference": "http:\/\/antivirus.neu.edu.cn\/scan\/",
                                                    "elapsed": "0.00",
                                                },
                                                "50": {
                                                    "engine": "NOC_RUB_DE",
                                                    "detected": False,
                                                    "reference": "https:\/\/noc.rub.de\/web\/",
                                                    "elapsed": "0.00",
                                                },
                                                "54": {
                                                    "engine": "NUBI Bad IPs",
                                                    "detected": False,
                                                    "reference": "https:\/\/www.nubi-network.com\/",
                                                    "elapsed": "0.00",
                                                },
                                                "49": {
                                                    "engine": "Nginx Bad Bot Blocker",
                                                    "detected": False,
                                                    "reference": "https:\/\/github.com\/mitchellkrogza\/nginx-ultimate-bad-bot-blocker",
                                                    "elapsed": "0.00",
                                                },
                                                "51": {
                                                    "engine": "NoIntegrity BL",
                                                    "detected": False,
                                                    "reference": "https:\/\/www.nointegrity.org\/",
                                                    "elapsed": "0.00",
                                                },
                                                "53": {
                                                    "engine": "NoVirusThanks",
                                                    "detected": False,
                                                    "reference": "https:\/\/www.novirusthanks.com\/",
                                                    "elapsed": "0.00",
                                                },
                                                "52": {
                                                    "engine": "NordSpam",
                                                    "detected": False,
                                                    "reference": "https:\/\/www.nordspam.com\/",
                                                    "elapsed": "0.00",
                                                },
                                                "55": {
                                                    "engine": "OpenPhish",
                                                    "detected": False,
                                                    "reference": "https:\/\/www.openphish.com\/",
                                                    "elapsed": "0.00",
                                                },
                                                "59": {
                                                    "engine": "PSBL",
                                                    "detected": False,
                                                    "reference": "https:\/\/psbl.org\/",
                                                    "elapsed": "0.00",
                                                },
                                                "56": {
                                                    "engine": "Peter-s NUUG IP BL",
                                                    "detected": False,
                                                    "reference": "https:\/\/home.nuug.no\/~peter\/",
                                                    "elapsed": "0.00",
                                                },
                                                "57": {
                                                    "engine": "PhishTank",
                                                    "detected": False,
                                                    "reference": "https:\/\/www.phishtank.com\/",
                                                    "elapsed": "0.00",
                                                },
                                                "58": {
                                                    "engine": "PlonkatronixBL",
                                                    "detected": True,
                                                    "reference": "https:\/\/plonkatronix.com\/",
                                                    "elapsed": "0.00",
                                                },
                                                "62": {
                                                    "engine": "RJM Blocklist",
                                                    "detected": False,
                                                    "reference": "https:\/\/rjmblocklist.com\/",
                                                    "elapsed": "0.00",
                                                },
                                                "7": {
                                                    "engine": "RealtimeBLACKLIST",
                                                    "detected": False,
                                                    "reference": "https:\/\/realtimeblacklist.com\/",
                                                    "elapsed": "0.15",
                                                },
                                                "60": {
                                                    "engine": "Redstout Threat IP list",
                                                    "detected": True,
                                                    "reference": "https:\/\/www.redstout.com\/index.html",
                                                    "elapsed": "0.00",
                                                },
                                                "61": {
                                                    "engine": "Ring-u NOC",
                                                    "detected": False,
                                                    "reference": "https:\/\/portal.ring-u.com\/portal\/portal.php",
                                                    "elapsed": "0.00",
                                                },
                                                "63": {
                                                    "engine": "Rutgers Drop List",
                                                    "detected": False,
                                                    "reference": "https:\/\/www.rutgers.edu\/",
                                                    "elapsed": "0.00",
                                                },
                                                "8": {
                                                    "engine": "S5hbl",
                                                    "detected": True,
                                                    "reference": "https:\/\/www.usenix.org.uk\/content\/rbl.html",
                                                    "elapsed": "0.21",
                                                },
                                                "65": {
                                                    "engine": "SSL Blacklist",
                                                    "detected": False,
                                                    "reference": "https:\/\/sslbl.abuse.ch\/",
                                                    "elapsed": "0.00",
                                                },
                                                "64": {
                                                    "engine": "Sblam",
                                                    "detected": False,
                                                    "reference": "https:\/\/sblam.com\/",
                                                    "elapsed": "0.00",
                                                },
                                                "9": {
                                                    "engine": "SpamCop",
                                                    "detected": False,
                                                    "reference": "https:\/\/www.spamcop.net\/",
                                                    "elapsed": "0.03",
                                                },
                                                "66": {
                                                    "engine": "Talos IP Blacklist",
                                                    "detected": False,
                                                    "reference": "https:\/\/www.talosintelligence.com\/",
                                                    "elapsed": "0.00",
                                                },
                                                "69": {
                                                    "engine": "Threat Crowd",
                                                    "detected": False,
                                                    "reference": "https:\/\/www.threatcrowd.org\/",
                                                    "elapsed": "0.00",
                                                },
                                                "70": {
                                                    "engine": "Threat Sourcing",
                                                    "detected": False,
                                                    "reference": "https:\/\/www.threatsourcing.com\/",
                                                    "elapsed": "0.00",
                                                },
                                                "67": {
                                                    "engine": "ThreatLog",
                                                    "detected": False,
                                                    "reference": "https:\/\/www.threatlog.com\/",
                                                    "elapsed": "0.00",
                                                },
                                                "68": {
                                                    "engine": "Threatview",
                                                    "detected": False,
                                                    "reference": "https:\/\/threatview.io\/",
                                                    "elapsed": "0.00",
                                                },
                                                "71": {
                                                    "engine": "TweetFeed",
                                                    "detected": False,
                                                    "reference": "https:\/\/github.com\/0xDanielLopez\/TweetFeed",
                                                    "elapsed": "0.00",
                                                },
                                                "72": {
                                                    "engine": "UCEPROTECT Level 1",
                                                    "detected": False,
                                                    "reference": "https:\/\/www.uceprotect.net\/en\/index.php",
                                                    "elapsed": "0.00",
                                                },
                                                "73": {
                                                    "engine": "URLhaus",
                                                    "detected": False,
                                                    "reference": "https:\/\/urlhaus.abuse.ch\/",
                                                    "elapsed": "0.00",
                                                },
                                                "74": {
                                                    "engine": "USTC IP BL",
                                                    "detected": True,
                                                    "reference": "http:\/\/blackip.ustc.edu.cn\/",
                                                    "elapsed": "0.00",
                                                },
                                                "77": {
                                                    "engine": "VXVault",
                                                    "detected": False,
                                                    "reference": "http:\/\/vxvault.net\/ViriList.php",
                                                    "elapsed": "0.00",
                                                },
                                                "75": {
                                                    "engine": "ViriBack C2 Tracker",
                                                    "detected": False,
                                                    "reference": "https:\/\/tracker.viriback.com\/",
                                                    "elapsed": "0.00",
                                                },
                                                "76": {
                                                    "engine": "VoIP Blacklist",
                                                    "detected": False,
                                                    "reference": "https:\/\/www.voipbl.org\/",
                                                    "elapsed": "0.00",
                                                },
                                                "78": {
                                                    "engine": "ZeroDot1 Miner IPs",
                                                    "detected": False,
                                                    "elapsed": "0.00",
                                                },
                                            },
                                            "detections": 7,
                                            "engines_count": 79,
                                            "detection_rate": "9%",
                                            "scantime": "1.35",
                                        },
                                        "information": {
                                            "reverse_dns": "",
                                            "continent_code": "EU",
                                            "continent_name": "Europe",
                                            "country_code": "RO",
                                            "country_name": "Romania",
                                            "country_currency": "RON",
                                            "country_calling_code": "40",
                                            "region_name": "Bucuresti",
                                            "city_name": "Bucharest",
                                            "latitude": 44.432301,
                                            "longitude": 26.10607,
                                            "isp": "Pptechnology Limited",
                                            "asn": "AS47890",
                                        },
                                        "anonymity": {
                                            "is_proxy": False,
                                            "is_webproxy": False,
                                            "is_vpn": False,
                                            "is_hosting": False,
                                            "is_tor": False,
                                        },
                                        "risk_score": {"result": 100},
                                    }
                                },
                                "credits_remained": 24.76,
                                "estimated_queries": "309",
                                "elapsed_time": "2.58",
                                "success": True,
                            }
                        },
                        200,
                    ),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
