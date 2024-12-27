# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from logging import getLogger
from typing import Dict, List

from api_app.analyzers_manager.models import AnalyzerReport
from api_app.visualizers_manager.classes import Visualizer
from api_app.visualizers_manager.decorators import (
    visualizable_error_handler_with_params,
)
from api_app.visualizers_manager.enums import VisualizableIcon

logger = getLogger(__name__)


class StaticSampleAnalyzers(Visualizer):
    @classmethod
    def update(cls) -> bool:
        pass

    @visualizable_error_handler_with_params("Yara Signatures")
    def _yara_signatures(self):
        yara_report = self.analyzer_reports().get(config__name="Yara")
        signatures = [
            match["match"]
            for matches in yara_report.report.values()
            for match in matches
            if match.get("match", None)
        ]
        disable_signatures = not signatures
        return self.VList(
            name=self.Base(value="Yara Signatures", disable=disable_signatures),
            value=[
                self.Base(value=value, disable=disable_signatures)
                for value in signatures
            ],
            start_open=True,
            disable=disable_signatures,
        )

    @visualizable_error_handler_with_params("ClamAV Signatures")
    def _clamav_signatures(self):
        clamav_report = self.analyzer_reports().get(config__name="ClamAV")
        detections = clamav_report.report.get("detections", [])
        disable_signatures = not detections
        return self.VList(
            name=self.Base(value="ClamAV Signatures", disable=disable_signatures),
            value=[
                self.Base(value=value, disable=disable_signatures)
                for value in detections
            ],
            disable=disable_signatures,
        )

    @visualizable_error_handler_with_params("Mraptor")
    def _mraptor(self, analyzer_report):
        report = analyzer_report.report
        mraptor = report.get("mraptor", "")
        mraptor_match = False
        if mraptor == "suspicious":
            mraptor_match = True
        disable_signatures = not mraptor_match
        return self.Title(
            name=self.Base(value="Mraptor", disable=disable_signatures),
            value=self.Base(
                value="found" if mraptor_match else "", disable=disable_signatures
            ),
            disable=disable_signatures,
        )

    @visualizable_error_handler_with_params("XLMMacroDeobfuscator")
    def _xlm_macro_deobfuscator(self, analyzer_report):
        report = analyzer_report.report
        found_urls = []
        error = ""
        outputs = report.get("output", "")
        if outputs:
            self.decrypt = True
            for output in outputs:
                for elem in output.split("\n"):
                    elem = elem.strip().replace("'", "").replace('"', "")
                    if elem.startswith("http"):
                        found_urls.append(elem)
        elif report.get("error", ""):
            error = report["error"]

        disable_signatures = not found_urls

        return self.VList(
            name=self.Base(
                value="XLM Macro Deobfuscator",
                disable=disable_signatures,
                icon=VisualizableIcon.WARNING if error else None,
            ),
            value=(
                [error]
                if error
                else [
                    self.Base(value=value, disable=disable_signatures)
                    for value in found_urls
                ]
            ),
            disable=disable_signatures,
        )

    @visualizable_error_handler_with_params("Extracted CVEs")
    def _cves(self, analyzer_report):
        report = analyzer_report.report
        cves = report.get("extracted_CVEs", "")
        extracted_cves = []
        for cve_item in cves:
            extracted_cves.extend(cve_item.get("CVEs", []))
        disable_signatures = not extracted_cves
        return self.VList(
            name=self.Base(value="Extracted CVEs", disable=disable_signatures),
            value=[
                self.Base(value=value, disable=disable_signatures)
                for value in extracted_cves
            ],
            disable=disable_signatures,
        )

    @visualizable_error_handler_with_params("PDF Info")
    def _pdf_info(self):
        try:
            analyzer_report = self.analyzer_reports().get(config__name="PDF_Info")
        except AnalyzerReport.DoesNotExist:
            pdf_report = self.Title(
                self.Base(
                    value="PDF Info",
                    link="",
                ),
                self.Base(value="Not executed"),
                disable=True,
            )
            return pdf_report
        else:
            report = analyzer_report.report
            peepdf = report.get("peepdf", [])
            uris = []
            for stat in peepdf.get("stats", []):
                uris.extend(stat.get("uris", []))

            disable_signatures = not uris
            return self.VList(
                name=self.Base(
                    value="Extracted URLs from PDFs", disable=disable_signatures
                ),
                value=[
                    self.Base(value=value, disable=disable_signatures) for value in uris
                ],
                disable=disable_signatures,
            )

    @visualizable_error_handler_with_params("CAPA Info")
    def _capa_info(self):
        try:
            analyzer_report = self.analyzer_reports().get(config__name="CAPA_Info")
        except AnalyzerReport.DoesNotExist:
            virustotal_report = self.Title(
                self.Base(
                    value="CAPA Info",
                    link="",
                ),
                self.Base(value="Not executed"),
                disable=True,
            )
            return virustotal_report
        else:
            report = analyzer_report.report
            capa_rules = report.get("rules", {}).keys()
            disable_signatures = not capa_rules
            return self.VList(
                name=self.Base(value="CAPA Signatures", disable=disable_signatures),
                value=[
                    self.Base(value=value, disable=disable_signatures)
                    for value in capa_rules
                ],
                disable=disable_signatures,
            )

    @visualizable_error_handler_with_params("Blint Info")
    def _blint_info(self):
        try:
            analyzer_report = self.analyzer_reports().get(config__name="Blint")
        except AnalyzerReport.DoesNotExist:
            virustotal_report = self.Title(
                self.Base(
                    value="Blint Info",
                    link="",
                ),
                self.Base(value="Not executed"),
                disable=True,
            )
            return virustotal_report
        else:
            report = analyzer_report.report
            findings = report.get("findings", [])
            titles = [f.get("title", "") for f in findings]
            disable_signatures = not findings
            return self.VList(
                name=self.Base(value="Blint Signatures", disable=disable_signatures),
                value=[
                    self.Base(value=value, disable=disable_signatures)
                    for value in titles
                ],
                disable=disable_signatures,
            )

    def run(self) -> List[Dict]:
        page1 = self.Page(name="Signatures Info")
        page2 = self.Page(name="Docs Info")
        page3 = self.Page(name="Executables Info")

        h1 = self.HList(value=[self._yara_signatures(), self._clamav_signatures()])
        page1.add_level(
            self.Level(position=1, size=self.LevelSize.S_3, horizontal_list=h1)
        )

        doc_info = self.analyzer_reports().get(config__name="Doc_Info")

        h2 = self.HList(
            value=[
                self._mraptor(doc_info),
                self._xlm_macro_deobfuscator(),
                self._cves(doc_info),
                self._pdf_info(),
            ]
        )
        page2.add_level(
            self.Level(position=1, size=self.LevelSize.S_3, horizontal_list=h2)
        )

        h3 = self.HList(value=[self._capa_info(), self._blint_info()])
        page3.add_level(
            self.Level(position=1, size=self.LevelSize.S_3, horizontal_list=h3)
        )

        return [page1.to_dict(), page2.to_dict(), page3.to_dict()]

    @classmethod
    def _monkeypatch(cls):
        patches = []
        return super()._monkeypatch(patches=patches)
