"""In this module there are functions to extract the data required by
Passive DNS visualizer from the analyzers reports.
"""

import dataclasses
import datetime
import logging
from typing import List

from django.db.models import QuerySet

from api_app.analyzers_manager.models import AnalyzerReport
from api_app.analyzers_manager.observable_analyzers.circl_pdns import CIRCL_PDNS
from api_app.analyzers_manager.observable_analyzers.dnsdb import DNSdb
from api_app.analyzers_manager.observable_analyzers.mnemonic_pdns import (
    MnemonicPassiveDNS,
)
from api_app.analyzers_manager.observable_analyzers.otx import OTX
from api_app.analyzers_manager.observable_analyzers.robtex import Robtex
from api_app.analyzers_manager.observable_analyzers.threatminer import Threatminer
from api_app.analyzers_manager.observable_analyzers.validin import Validin
from api_app.models import Job, PythonModule

logger = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True)
class PDNSReport:
    last_view: str
    first_view: str
    rrtype: str
    rdata: str
    rrname: str
    source: str
    source_description: str


def _extract_analyzer(analyzer_reports: QuerySet, module: PythonModule, job: Job) -> AnalyzerReport:
    try:
        analyzer_report = analyzer_reports.get(config__python_module=module)
        printable_analyzer_name = analyzer_report.config.name.replace("_", " ")
        logger.debug(f"{printable_analyzer_name=}")
    except AnalyzerReport.DoesNotExist:
        logger.warning(f"job: {job.id}, {module} analyzer report doesn't exist")
        return None
    return analyzer_report


def extract_otxquery_reports(analyzer_reports: QuerySet, job: Job) -> List[PDNSReport]:
    otx_analyzer = _extract_analyzer(analyzer_reports, OTX.python_module, job)
    if otx_analyzer:
        otx_reports = otx_analyzer.report.get("passive_dns", [])
        pdns_reports = []
        for report in otx_reports:
            pdns_report = PDNSReport(
                report.get("last").split("T")[0],
                report.get("first").split("T")[0],
                report.get("record_type"),
                report.get("address"),
                report.get("hostname"),
                otx_analyzer.config.name.replace("_", " "),
                otx_analyzer.config.description,
            )
            pdns_reports.append(pdns_report)
        return pdns_reports
    return []


def extract_threatminer_reports(analyzer_reports: QuerySet, job: Job) -> List[PDNSReport]:
    threatminer_analyzer = _extract_analyzer(analyzer_reports, Threatminer.python_module, job)
    if threatminer_analyzer:
        threatminer_reports = threatminer_analyzer.report.get("results", [])
        pdns_reports = []
        for report in threatminer_reports:
            pdns_report = PDNSReport(
                report.get("last_seen").split(" ")[0],
                report.get("first_seen").split(" ")[0],
                "A",
                report.get("ip", None) or report.get("domain", None),
                job.analyzable.name,
                threatminer_analyzer.config.name.replace("_", " "),
                threatminer_analyzer.config.description,
            )
            pdns_reports.append(pdns_report)
        return pdns_reports
    return []


def extract_validin_reports(analyzer_reports: QuerySet, job: Job) -> List[PDNSReport]:
    validin_analyzer = _extract_analyzer(analyzer_reports, Validin.python_module, job)
    if validin_analyzer:
        records = validin_analyzer.report.get("records", [])
        validin_reports = []
        if records:
            for [records_type, values] in records.items():
                for value in values:
                    value.update({"type": records_type})
                    validin_reports.append(value)
        pdns_reports = []
        for report in validin_reports:
            pdns_report = PDNSReport(
                datetime.datetime.fromtimestamp(report.get("last_seen")).strftime("%Y-%m-%d"),
                datetime.datetime.fromtimestamp(report.get("first_seen")).strftime("%Y-%m-%d"),
                report.get("type"),
                report.get("value"),
                report.get("key"),
                validin_analyzer.config.name.replace("_", " "),
                validin_analyzer.config.description,
            )
            pdns_reports.append(pdns_report)
        return pdns_reports
    return []


def extract_dnsdb_reports(analyzer_reports: QuerySet, job: Job) -> List[PDNSReport]:
    dnsdb_analyzer = _extract_analyzer(analyzer_reports, DNSdb.python_module, job)
    if dnsdb_analyzer:
        dnsdb_reports = dnsdb_analyzer.report.get("data", [])
        pdns_reports = []
        for report in dnsdb_reports:
            pdns_report = PDNSReport(
                datetime.datetime.fromtimestamp(report.get("time_last")).strftime("%Y-%m-%d"),
                datetime.datetime.fromtimestamp(report.get("time_first")).strftime("%Y-%m-%d"),
                report.get("rrtype"),
                report.get("rdata"),
                report.get("rrname"),
                dnsdb_analyzer.config.name.replace("_", " "),
                dnsdb_analyzer.config.description,
            )
            pdns_reports.append(pdns_report)
        return pdns_reports
    return []


def extract_circlpdns_reports(analyzer_reports: QuerySet, job: Job) -> List[PDNSReport]:
    circlpdns_analyzer = _extract_analyzer(analyzer_reports, CIRCL_PDNS.python_module, job)
    if circlpdns_analyzer:
        circlpdns_reports = circlpdns_analyzer.report
        pdns_reports = []
        for report in circlpdns_reports:
            pdns_report = PDNSReport(
                datetime.datetime.fromtimestamp(report.get("time_last")).strftime("%Y-%m-%d"),
                datetime.datetime.fromtimestamp(report.get("time_first")).strftime("%Y-%m-%d"),
                report.get("rrtype"),
                report.get("rdata"),
                report.get("rrname"),
                circlpdns_analyzer.config.name.replace("_", " "),
                circlpdns_analyzer.config.description,
            )
            pdns_reports.append(pdns_report)
        return pdns_reports
    return []


def extract_robtex_reports(analyzer_reports: QuerySet, job: Job) -> List[PDNSReport]:
    robtex_analyzer = _extract_analyzer(analyzer_reports, Robtex.python_module, job)
    if robtex_analyzer:
        robtex_reports = robtex_analyzer.report
        pdns_reports = []
        for report in robtex_reports:
            if "rrdata" in report.keys():
                pdns_report = PDNSReport(
                    datetime.datetime.fromtimestamp(report.get("time_last")).strftime("%Y-%m-%d"),
                    datetime.datetime.fromtimestamp(report.get("time_first")).strftime("%Y-%m-%d"),
                    report.get("rrtype"),
                    report.get("rrdata"),
                    report.get("rrname"),
                    robtex_analyzer.config.name.replace("_", " "),
                    robtex_analyzer.config.description,
                )
                pdns_reports.append(pdns_report)
        return pdns_reports
    return []


def extract_mnemonicpdns_reports(analyzer_reports: QuerySet, job: Job) -> List[PDNSReport]:
    mnemonicpdns_analyzer = _extract_analyzer(analyzer_reports, MnemonicPassiveDNS.python_module, job)
    if mnemonicpdns_analyzer:
        mnemonicpdns_reports = mnemonicpdns_analyzer.report
        pdns_reports = []
        for report in mnemonicpdns_reports:
            pdns_report = PDNSReport(
                datetime.datetime.fromtimestamp(report.get("time_last")).strftime("%Y-%m-%d"),
                datetime.datetime.fromtimestamp(report.get("time_first")).strftime("%Y-%m-%d"),
                report.get("rrtype"),
                report.get("rdata"),
                report.get("rrname"),
                mnemonicpdns_analyzer.config.name.replace("_", " "),
                mnemonicpdns_analyzer.config.description,
            )
            pdns_reports.append(pdns_report)
        return pdns_reports
    return []
