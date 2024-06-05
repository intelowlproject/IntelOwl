import datetime
from logging import getLogger
from typing import Dict, List

from api_app.analyzers_manager.models import AnalyzerReport
from api_app.visualizers_manager.classes import VisualizableObject, Visualizer
from api_app.visualizers_manager.decorators import (
    visualizable_error_handler_with_params,
)

logger = getLogger(__name__)


class PassiveDNS(Visualizer):
    def _threatminer_report(self, report):
        # EXAMPLE REPORT
        # {
        #     "results": [
        #         {
        #             "ip": "69.172.200.235",
        #             "last_seen": "2019-12-03 21:28:00",
        #             "first_seen": "2015-07-08 00:00:00"
        #         },
        #   DA GESTIRE
        #         {
        #             "domain": "dns.google",
        #             "last_seen": "2015-01-19 00:00:00",
        #             "first_seen": "2015-01-19 00:00:00"
        #         },
        #     ],
        #     "status_code": "200",
        #     "status_message": "Results found."
        # }
        obj = {}
        for [key, value] in report.items():
            if key == "last_seen":
                obj.update(
                    {
                        "time_last": Visualizer.Base(
                            value=value.split(" ")[0],
                            color=Visualizer.Color.TRANSPARENT,
                            disable=False,
                        )
                    }
                )
            elif key == "first_seen":
                obj.update(
                    {
                        "time_first": Visualizer.Base(
                            value=value.split(" ")[0],
                            color=Visualizer.Color.TRANSPARENT,
                            disable=False,
                        )
                    }
                )
            elif key == "ip":
                obj.update(
                    {
                        "rdata": Visualizer.Base(
                            value=value,
                            color=Visualizer.Color.TRANSPARENT,
                            disable=False,
                        )
                    }
                )
            obj.update(
                {
                    "rrtype": Visualizer.Base(
                        value="a", color=Visualizer.Color.TRANSPARENT, disable=False
                    )
                }
            )
            obj.update(
                {
                    "rrname": Visualizer.Base(
                        value="null", color=Visualizer.Color.TRANSPARENT, disable=True
                    )
                }
            )
        return obj

    def _otx_report(self, report):
        # EXAMPLE REPORT
        # {
        #     passive_dns: [
        #         {
        #             "address": "NXDOMAIN", ---> rdata
        #             "first": "2023-12-01T13:24:37",
        #             "last": "2023-12-01T13:24:37",
        #             "hostname": "dns.vietbaotinmoi.com",  ----> rname
        #             "record_type": "A",
        #             "indicator_link": "/indicator/hostname/dns.vietbaotinmoi.com",
        #             "flag_url": "",
        #             "flag_title": "",
        #             "asset_type": "hostname",
        #             "asn": null,
        #             "suspicious": true,
        #             "whitelisted_message": [],
        #             "whitelisted": false
        #         },
        #       {
        #     "address": "195.22.26.248", ---> rdata
        #     "first": "2022-03-19T17:14:00",
        #     "last": "2022-03-19T17:16:33",
        #     "hostname": "4ed8a7c6.ard.rr.zealbino.com", ----> rname
        #     "record_type": "A",
        #     "indicator_link": "/indicator/hostname/4ed8a7c6.ard.rr.zealbino.com",
        #     "flag_url": "assets/images/flags/pt.png",
        #     "flag_title": "Portugal",
        #     "asset_type": "hostname",
        #     "asn": "AS8426 claranet ltd",
        #     "suspicious": false,
        #     "whitelisted_message": [],
        #     "whitelisted": false
        # },
        #     ]
        # }
        obj = {}
        for [key, value] in report.items():
            if key == "last":
                obj.update(
                    {
                        "time_last": Visualizer.Base(
                            value=value.split("T")[0],
                            color=Visualizer.Color.TRANSPARENT,
                            disable=False,
                        )
                    }
                )
            elif key == "first":
                obj.update(
                    {
                        "time_first": Visualizer.Base(
                            value=value.split("T")[0],
                            color=Visualizer.Color.TRANSPARENT,
                            disable=False,
                        )
                    }
                )
            elif key == "record_type":
                obj.update(
                    {
                        "rrtype": Visualizer.Base(
                            value=value,
                            color=Visualizer.Color.TRANSPARENT,
                            disable=False,
                        )
                    }
                )
            elif key == "address":
                if isinstance(value, list):
                    obj.update(
                        {
                            "rdata": Visualizer.VList(
                                value=[
                                    Visualizer.Base(
                                        value=data,
                                        color=Visualizer.Color.TRANSPARENT,
                                        disable=False,
                                    )
                                    for data in value
                                ],
                                disable=not value,
                            ),
                        }
                    )
                else:
                    obj.update(
                        {
                            "rdata": Visualizer.Base(
                                value=value,
                                color=Visualizer.Color.TRANSPARENT,
                                disable=False,
                            )
                        }
                    )
            elif key == "hostname":
                obj.update(
                    {
                        "rrname": Visualizer.Base(
                            value=value,
                            color=Visualizer.Color.TRANSPARENT,
                            disable=False,
                        )
                    }
                )
        return obj

    def _report_data(self, analyzer_report: AnalyzerReport) -> List:
        printable_analyzer_name = analyzer_report.config.name.replace("_", " ")
        logger.debug(f"{printable_analyzer_name=}")
        reports = []
        if "threatminer.Threatminer" in analyzer_report.config.python_module:
            reports = analyzer_report.report["results"]
        elif "otx.OTX" in analyzer_report.config.python_module:
            reports = analyzer_report.report.get("passive_dns", [])
        else:
            reports = analyzer_report.report
        # EXAMPLE REPORT - MnemonicPassiveDNS
        # {
        #       "count": 4477,
        #       "rdata": "34.224.149.186",
        #       "rrname": "test.com",
        #       "rrtype": "a",
        #       "time_last": 1714654257,
        #       "time_first": 1712319486
        # }
        # EXAMPLE REPORT - Robtex
        # {
        #       "count": 2,
        #       "rrdata": "mx.spamexperts.com",
        #       "rrname": "test.com",
        #       "rrtype": "MX",
        #       "time_last": 1582215078,
        #       "time_first": 1441363932
        # }
        # EXAMPLE REPORT - CIRCL_PDNS
        # {
        #     "rrtype": "A",
        #     "rrname": "185.194.93.14",
        #     "rdata": "circl.lu",
        #     "count": "19",
        #     "time_first": "1696798385",
        #     "time_last": "1697890824"
        # }
        ui_data = []
        for report in reports:
            obj = {}
            if "threatminer.Threatminer" in analyzer_report.config.python_module:
                obj = self._threatminer_report(report)
            if "otx.OTX" in analyzer_report.config.python_module:
                obj = self._otx_report(report)
            for [key, value] in report.items():
                if key in ["time_first", "time_last"]:
                    timestamp = datetime.datetime.fromtimestamp(value)
                    obj.update(
                        {
                            key: Visualizer.Base(
                                value=timestamp.strftime("%Y-%m-%d"),
                                color=Visualizer.Color.TRANSPARENT,
                                disable=False,
                            )
                        }
                    )
                elif key in ["rrname", "rrtype", "count"]:
                    obj.update(
                        {
                            key: Visualizer.Base(
                                value=value,
                                color=Visualizer.Color.TRANSPARENT,
                                disable=False,
                            )
                        }
                    )
                elif key in ["rrdata", "rdata"]:
                    if isinstance(value, list):
                        obj.update(
                            {
                                "rdata": Visualizer.VList(
                                    value=[
                                        Visualizer.Base(
                                            value=data,
                                            color=Visualizer.Color.TRANSPARENT,
                                            disable=False,
                                        )
                                        for data in value
                                    ],
                                    disable=not value,
                                ),
                            }
                        )
                    else:
                        obj.update(
                            {
                                "rdata": Visualizer.Base(
                                    value=value,
                                    color=Visualizer.Color.TRANSPARENT,
                                    disable=False,
                                )
                            }
                        )
            if obj:
                obj.update(
                    {
                        "source": Visualizer.Base(
                            value=printable_analyzer_name,
                            color=Visualizer.Color.TRANSPARENT,
                            disable=False,
                            description=analyzer_report.config.description,
                        )
                    }
                )
                ui_data.append(obj)
        return ui_data

    @visualizable_error_handler_with_params("pdns_table")
    def _pdns_table_ui(self) -> VisualizableObject:
        reports_data = []
        for analyzer_report in self.analyzer_reports():
            reports_data.extend(self._report_data(analyzer_report=analyzer_report))

        return [
            self.Table(
                data=reports_data,
                columns=[
                    "time_last",
                    "time_first",
                    "rrname",
                    "rrtype",
                    "rdata",
                    "source",
                ],
                size=self.Size.S_ALL,
                disable_sort_by=True,
                page_size=10,
            )
        ]

    def run(self) -> List[Dict]:
        page = self.Page(name="Passive DNS")
        page.add_level(
            self.Level(
                position=1,
                size=self.LevelSize.S_6,
                horizontal_list=self.HList(value=self._pdns_table_ui()),
            )
        )
        logger.debug(f"levels: {page.to_dict()}")
        return [page.to_dict()]

    @classmethod
    def _monkeypatch(cls):
        patches = []
        return super()._monkeypatch(patches=patches)
