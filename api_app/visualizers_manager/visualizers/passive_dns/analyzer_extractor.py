"""In this module there are functions to extract the data required by
Passive DNS visualizer from the analyzers reports.
"""

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


def _extract_analyzer(
    analyzer_reports: QuerySet, module: PythonModule, job: Job
) -> AnalyzerReport:
    try:
        analyzer_report = analyzer_reports.get(config__python_module=module)
        printable_analyzer_name = analyzer_report.config.name.replace("_", " ")
        logger.debug(f"{printable_analyzer_name=}")
    except AnalyzerReport.DoesNotExist:
        logger.warning(f"job: {job.id}, {module} analyzer report doesn't exist")
        return None
    return analyzer_report


def extract_otxquery_reports(analyzer_reports: QuerySet, job: Job) -> List:
    otx_analyzer = _extract_analyzer(analyzer_reports, OTX.python_module, job)
    if otx_analyzer:
        otx_reports = otx_analyzer.report.get("passive_dns", [])
        for report in otx_reports:
            report["last_view"] = report.pop("last").split("T")[0]
            report["first_view"] = report.pop("first").split("T")[0]
            report["rrtype"] = report.pop("record_type")
            report["rdata"] = report.pop("address")
            report["rrname"] = report.pop("hostname")
            report["source"] = otx_analyzer.config.name.replace("_", " ")
            report["source_description"] = otx_analyzer.config.description
        return otx_reports
    return []


def extract_threatminer_reports(analyzer_reports: QuerySet, job: Job) -> List:
    threatminer_analyzer = _extract_analyzer(
        analyzer_reports, Threatminer.python_module, job
    )
    if threatminer_analyzer:
        threatminer_reports = threatminer_analyzer.report.get("results", [])
        for report in threatminer_reports:
            report["last_view"] = report.pop("last_seen").split(" ")[0]
            report["first_view"] = report.pop("first_seen").split(" ")[0]
            report["rrtype"] = "A"
            report["rdata"] = report.pop("ip", None) or report.pop(
                "domain", None
            )  # verificare che sta roba funzioni
            report["rrname"] = job.observable_name
            report["source"] = threatminer_analyzer.config.name.replace("_", " ")
            report["source_description"] = threatminer_analyzer.config.description
        return threatminer_reports
    return []


def extract_validin_reports(analyzer_reports: QuerySet, job: Job) -> List:
    validin_analyzer = _extract_analyzer(analyzer_reports, Validin.python_module, job)
    if validin_analyzer:
        records = validin_analyzer.report.get("records", [])
        validin_reports = []
        if records:
            for [records_type, values] in records.items():
                for value in values:
                    value.update({"type": records_type})
                    validin_reports.append(value)
        for report in validin_reports:
            report["last_view"] = datetime.datetime.fromtimestamp(
                report.pop("last_seen")
            ).strftime("%Y-%m-%d")
            report["first_view"] = datetime.datetime.fromtimestamp(
                report.pop("first_seen")
            ).strftime("%Y-%m-%d")
            report["rrtype"] = report.pop("type")
            report["rdata"] = report.pop("value")
            report["rrname"] = report.pop("key")
            report["source"] = validin_analyzer.config.name.replace("_", " ")
            report["source_description"] = validin_analyzer.config.description
        return validin_reports
    return []


def extract_dnsdb_reports(analyzer_reports: QuerySet, job: Job) -> List:
    dnsdb_analyzer = _extract_analyzer(analyzer_reports, DNSdb.python_module, job)
    if dnsdb_analyzer:
        dnsdb_reports = dnsdb_analyzer.report.get("data", [])
        for report in dnsdb_reports:
            report["last_view"] = datetime.datetime.fromtimestamp(
                report.pop("time_last")
            ).strftime("%Y-%m-%d")
            report["first_view"] = datetime.datetime.fromtimestamp(
                report.pop("time_first")
            ).strftime("%Y-%m-%d")
            report["source"] = dnsdb_analyzer.config.name.replace("_", " ")
            report["source_description"] = dnsdb_analyzer.config.description
        return dnsdb_reports
    return []


def extract_circlpdns_reports(analyzer_reports: QuerySet, job: Job) -> List:
    circlpdns_analyzer = _extract_analyzer(
        analyzer_reports, CIRCL_PDNS.python_module, job
    )
    if circlpdns_analyzer:
        circlpdns_reports = circlpdns_analyzer.report
        for report in circlpdns_reports:
            report["last_view"] = datetime.datetime.fromtimestamp(
                report.pop("time_last")
            ).strftime("%Y-%m-%d")
            report["first_view"] = datetime.datetime.fromtimestamp(
                report.pop("time_first")
            ).strftime("%Y-%m-%d")
            report["source"] = circlpdns_analyzer.config.name.replace("_", " ")
            report["source_description"] = circlpdns_analyzer.config.description
        return circlpdns_reports
    return []


def extract_robtex_reports(analyzer_reports: QuerySet, job: Job) -> List:
    robtex_analyzer = _extract_analyzer(analyzer_reports, Robtex.python_module, job)
    if robtex_analyzer:
        robtex_reports = robtex_analyzer.report
        for report in robtex_reports:
            report["last_view"] = datetime.datetime.fromtimestamp(
                report.pop("time_last")
            ).strftime("%Y-%m-%d")
            report["first_view"] = datetime.datetime.fromtimestamp(
                report.pop("time_first")
            ).strftime("%Y-%m-%d")
            report["rdata"] = report.pop("rrdata")
            report["source"] = robtex_analyzer.config.name.replace("_", " ")
            report["source_description"] = robtex_analyzer.config.description
        return robtex_reports
    return []


def extract_mnemonicpdns_reports(analyzer_reports: QuerySet, job: Job) -> List:
    mnemonicpdns_analyzer = _extract_analyzer(
        analyzer_reports, MnemonicPassiveDNS.python_module, job
    )
    if mnemonicpdns_analyzer:
        mnemonicpdns_reports = mnemonicpdns_analyzer.report
        for report in mnemonicpdns_reports:
            report["last_view"] = datetime.datetime.fromtimestamp(
                report.pop("time_last")
            ).strftime("%Y-%m-%d")
            report["first_view"] = datetime.datetime.fromtimestamp(
                report.pop("time_first")
            ).strftime("%Y-%m-%d")
            report["source"] = mnemonicpdns_analyzer.config.name.replace("_", " ")
            report["source_description"] = mnemonicpdns_analyzer.config.description
        return mnemonicpdns_reports
    return []
