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
    @classmethod
    def update(cls) -> bool:
        pass

    def _threatminer_reports(self) -> List:
        try:
            analyzer_report = self.analyzer_reports().get(config__name="Threatminer")
            printable_analyzer_name = analyzer_report.config.name.replace("_", " ")
            logger.debug(f"{printable_analyzer_name=}")
        except AnalyzerReport.DoesNotExist:
            logger.warning("Threatminer report does not exist")
            return []
        else:
            reports = analyzer_report.report.get("results", [])
            threatminer_report = []
            for report in reports:
                obj = {}
                for [key, value] in report.items():
                    if key == "last_seen":
                        obj.update(
                            {
                                "last_view": Visualizer.Base(
                                    value=value.split(" ")[0],
                                    color=Visualizer.Color.TRANSPARENT,
                                    disable=False,
                                )
                            }
                        )
                    elif key == "first_seen":
                        obj.update(
                            {
                                "first_view": Visualizer.Base(
                                    value=value.split(" ")[0],
                                    color=Visualizer.Color.TRANSPARENT,
                                    disable=False,
                                )
                            }
                        )
                    elif key in ["ip", "domain"]:
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
                                value="A",
                                color=Visualizer.Color.TRANSPARENT,
                                disable=False,
                            )
                        }
                    )
                    obj.update(
                        {
                            "rrname": Visualizer.Base(
                                value="null",
                                color=Visualizer.Color.TRANSPARENT,
                                disable=True,
                            )
                        }
                    )
                if obj:
                    obj.update(
                        {"source": self._visualizable_source(analyzer_report.config)}
                    )
                    threatminer_report.append(obj)
            return threatminer_report

    def _otxquery_reports(self) -> List:
        try:
            analyzer_report = self.analyzer_reports().get(config__name="OTXQuery")
            printable_analyzer_name = analyzer_report.config.name.replace("_", " ")
            logger.debug(f"{printable_analyzer_name=}")
        except AnalyzerReport.DoesNotExist:
            logger.warning("OTXQuery report does not exist")
            return []
        else:
            reports = analyzer_report.report.get("passive_dns", [])
            otx_report = []
            for report in reports:
                obj = {}
                for [key, value] in report.items():
                    if key == "last":
                        obj.update(
                            {
                                "last_view": Visualizer.Base(
                                    value=value.split("T")[0],
                                    color=Visualizer.Color.TRANSPARENT,
                                    disable=False,
                                )
                            }
                        )
                    elif key == "first":
                        obj.update(
                            {
                                "first_view": Visualizer.Base(
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
                                    value=value.upper(),
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
                if obj:
                    obj.update(
                        {"source": self._visualizable_source(analyzer_report.config)}
                    )
                    otx_report.append(obj)
            return otx_report

    def _validin_reports(self) -> List:
        try:
            analyzer_report = self.analyzer_reports().get(config__name="Validin")
            printable_analyzer_name = analyzer_report.config.name.replace("_", " ")
            logger.debug(f"{printable_analyzer_name=}")
        except AnalyzerReport.DoesNotExist:
            logger.warning("Validin report does not exist")
            return []
        else:
            records = analyzer_report.report.get("records", [])
            reports = []
            if records:
                for [records_type, values] in records.items():
                    for value in values:
                        value.update({"type": records_type})
                        reports.append(value)
            validin_report = []
            for report in reports:
                obj = {}
                for [key, value] in report.items():
                    if key == "last_seen":
                        timestamp = datetime.datetime.fromtimestamp(value)
                        obj.update(
                            {
                                "last_view": Visualizer.Base(
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
                                "first_view": Visualizer.Base(
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
                                    value=value.upper(),
                                    color=Visualizer.Color.TRANSPARENT,
                                    disable=False,
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
                if obj:
                    obj.update(
                        {"source": self._visualizable_source(analyzer_report.config)}
                    )
                    validin_report.append(obj)
            return validin_report

    def _dnsdb_reports(self) -> List:
        try:
            analyzer_report = self.analyzer_reports().get(config__name="DNSDB")
            printable_analyzer_name = analyzer_report.config.name.replace("_", " ")
            logger.debug(f"{printable_analyzer_name=}")
        except AnalyzerReport.DoesNotExist:
            logger.warning("DNSDB report does not exist")
            return []
        else:
            reports = analyzer_report.report.get("data", [])
            dnsdb_report = []
            for report in reports:
                obj = self._report_data(report)
                if obj:
                    obj.update(
                        {"source": self._visualizable_source(analyzer_report.config)}
                    )
                    dnsdb_report.append(obj)
            return dnsdb_report

    def _circl_pdns_reports(self) -> List:
        try:
            analyzer_report = self.analyzer_reports().get(
                config__name="CIRCLPassiveDNS"
            )
            printable_analyzer_name = analyzer_report.config.name.replace("_", " ")
            logger.debug(f"{printable_analyzer_name=}")
        except AnalyzerReport.DoesNotExist:
            logger.warning("CIRCLPassiveDNS report does not exist")
            return []
        else:
            reports = analyzer_report.report
            circl_pdns_report = []
            for report in reports:
                obj = self._report_data(report)
                if obj:
                    obj.update(
                        {"source": self._visualizable_source(analyzer_report.config)}
                    )
                    circl_pdns_report.append(obj)
            return circl_pdns_report

    def _robtex_reports(self) -> List:
        try:
            analyzer_report = self.analyzer_reports().get(config__name="Robtex")
            printable_analyzer_name = analyzer_report.config.name.replace("_", " ")
            logger.debug(f"{printable_analyzer_name=}")
        except AnalyzerReport.DoesNotExist:
            logger.warning("Robtex report does not exist")
            return []
        else:
            reports = analyzer_report.report
            robtex_report = []
            for report in reports:
                obj = self._report_data(report)
                if obj:
                    obj.update(
                        {"source": self._visualizable_source(analyzer_report.config)}
                    )
                    robtex_report.append(obj)
            return robtex_report

    def _mnemonic_pdns_reports(self) -> List:
        try:
            analyzer_report = self.analyzer_reports().get(
                config__name="Mnemonic_PassiveDNS"
            )
            printable_analyzer_name = analyzer_report.config.name.replace("_", " ")
            logger.debug(f"{printable_analyzer_name=}")
        except AnalyzerReport.DoesNotExist:
            logger.warning("Mnemonic_PassiveDNS report does not exist")
            return []
        else:
            reports = analyzer_report.report
            mnemonic_pdns_report = []
            for report in reports:
                obj = self._report_data(report)
                if obj:
                    obj.update(
                        {"source": self._visualizable_source(analyzer_report.config)}
                    )
                    mnemonic_pdns_report.append(obj)
            return mnemonic_pdns_report

    def _report_data(self, report) -> List:
        obj = {}
        for [key, value] in report.items():
            if key == "time_first":
                timestamp = datetime.datetime.fromtimestamp(value)
                obj.update(
                    {
                        "first_view": Visualizer.Base(
                            value=timestamp.strftime("%Y-%m-%d"),
                            color=Visualizer.Color.TRANSPARENT,
                            disable=False,
                        )
                    }
                )
            elif key == "time_last":
                timestamp = datetime.datetime.fromtimestamp(value)
                obj.update(
                    {
                        "last_view": Visualizer.Base(
                            value=timestamp.strftime("%Y-%m-%d"),
                            color=Visualizer.Color.TRANSPARENT,
                            disable=False,
                        )
                    }
                )
            elif key in ["rrname", "count"]:
                obj.update(
                    {
                        key: Visualizer.Base(
                            value=value,
                            color=Visualizer.Color.TRANSPARENT,
                            disable=False,
                        )
                    }
                )
            elif key == "rrtype":
                obj.update(
                    {
                        key: Visualizer.Base(
                            value=value.upper(),
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
        return obj

    def _visualizable_source(self, analyzer_config) -> VisualizableObject:
        return Visualizer.Base(
            value=analyzer_config.name.replace("_", " "),
            color=Visualizer.Color.TRANSPARENT,
            disable=False,
            description=analyzer_config.description,
        )

    @visualizable_error_handler_with_params("pdns_table")
    def _pdns_table_ui(self) -> VisualizableObject:
        reports_data = []
        reports_data.extend(self._otxquery_reports())
        reports_data.extend(self._threatminer_reports())
        reports_data.extend(self._validin_reports())
        reports_data.extend(self._dnsdb_reports())
        reports_data.extend(self._circl_pdns_reports())
        reports_data.extend(self._robtex_reports())
        reports_data.extend(self._mnemonic_pdns_reports())

        columns = [
            Visualizer.TableColumn(
                name="last_view",
                max_width=VisualizableTableColumnSize.S_100,
                description="""The last time that the unique tuple"
                 (rrname, rrtype, rdata) record has been seen by the passive DNS.""",
            ),
            Visualizer.TableColumn(
                name="first_view",
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
                max_width=VisualizableTableColumnSize.S_50,
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
                sort_by_id="last_view",
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
