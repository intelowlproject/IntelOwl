import datetime
from logging import getLogger
from typing import Dict, List

from api_app.analyzers_manager.models import AnalyzerReport
from api_app.visualizers_manager.classes import VisualizableObject, Visualizer
from api_app.visualizers_manager.decorators import (
    visualizable_error_handler_with_params,
)
from api_app.visualizers_manager.enums import VisualizableTableColumnSize

logger = getLogger(__name__)


class PassiveDNS(Visualizer):
    def _threatminer_report(self, report):
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
            elif key == "ip" or key == "domain":
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
                        value="A", color=Visualizer.Color.TRANSPARENT, disable=False
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

    def _validin_report(self, report):
        obj = {}
        for [key, value] in report.items():
            if key == "last_seen":
                timestamp = datetime.datetime.fromtimestamp(value)
                obj.update(
                    {
                        "time_last": Visualizer.Base(
                            value=timestamp.strftime("%Y-%m-%d"),
                            color=Visualizer.Color.TRANSPARENT,
                            disable=False,
                        )
                    }
                )
            elif key == "first_seen":
                timestamp = datetime.datetime.fromtimestamp(value)
                obj.update(
                    {
                        "time_first": Visualizer.Base(
                            value=timestamp.strftime("%Y-%m-%d"),
                            color=Visualizer.Color.TRANSPARENT,
                            disable=False,
                        )
                    }
                )
            elif key == "key":
                obj.update(
                    {
                        "rrname": Visualizer.Base(
                            value=value,
                            color=Visualizer.Color.TRANSPARENT,
                            disable=False,
                        )
                    }
                )
            elif key == "type":
                obj.update(
                    {
                        "rrtype": Visualizer.Base(
                            value="A", color=Visualizer.Color.TRANSPARENT, disable=False
                        )
                    }
                )
            elif key == "value":
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
        return obj

    def _report_data(self, analyzer_report: AnalyzerReport) -> List:
        printable_analyzer_name = analyzer_report.config.name.replace("_", " ")
        logger.debug(f"{printable_analyzer_name=}")
        reports = []
        if "threatminer.Threatminer" in analyzer_report.config.python_module:
            reports = analyzer_report.report.get("results", [])
        elif "otx.OTX" in analyzer_report.config.python_module:
            reports = analyzer_report.report.get("passive_dns", [])
        elif "dnsdb.DNSdb" in analyzer_report.config.python_module:
            reports = analyzer_report.report.get("data", [])
        elif "validin.Validin" in analyzer_report.config.python_module:
            records = analyzer_report.report.get("records", [])
            if records:
                for [type, values] in records.items():
                    for value in values:
                        value.update({"type": type})
                        reports.append(value)
        else:
            reports = analyzer_report.report

        ui_data = []
        for report in reports:
            obj = {}
            if "threatminer.Threatminer" in analyzer_report.config.python_module:
                obj = self._threatminer_report(report)
            if "otx.OTX" in analyzer_report.config.python_module:
                obj = self._otx_report(report)
            if "validin.Validin" in analyzer_report.config.python_module:
                obj = self._validin_report(report)
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

        columns = [
            Visualizer.TableColumn(
                name="time_last",
                max_width=VisualizableTableColumnSize.S_100,
                description="""This field returns the last time that the unique tuple"
                 (rrname, rrtype, rdata) record has been seen by the passive DNS.""",
            ),
            Visualizer.TableColumn(
                name="time_first",
                max_width=VisualizableTableColumnSize.S_100,
                description="""The first time that the record / unique tuple
                 (rrname, rrtype, rdata) has been seen by the passive DNS.""",
            ),
            Visualizer.TableColumn(
                name="rrname",
                max_width=VisualizableTableColumnSize.S_300,
                disable_sort_by=True,
                description="Name of the queried resource.",
            ),
            Visualizer.TableColumn(
                name="rrtype",
                max_width=VisualizableTableColumnSize.S_100,
                disable_sort_by=True,
                description="Record type as seen by the passive DNS.",
            ),
            Visualizer.TableColumn(
                name="rdata",
                max_width=VisualizableTableColumnSize.S_300,
                disable_sort_by=True,
                description="Resource records of the queried resource.",
            ),
            Visualizer.TableColumn(
                name="source",
                max_width=VisualizableTableColumnSize.S_200,
                disable_sort_by=True,
            ),
        ]

        return [
            self.Table(
                data=reports_data,
                columns=columns,
                size=self.Size.S_ALL,
                page_size=10,
                sort_by_id="time_last",
                sort_by_desc=True,
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
