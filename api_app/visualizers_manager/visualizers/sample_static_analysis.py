# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from logging import getLogger
from typing import Dict, List

from api_app.analyzers_manager.models import AnalyzerReport
from api_app.choices import ReportStatus
from api_app.visualizers_manager.classes import Visualizer
from api_app.visualizers_manager.decorators import (
    visualizable_error_handler_with_params,
)
from api_app.visualizers_manager.enums import (
    VisualizableColor,
    VisualizableIcon,
)

logger = getLogger(__name__)


class SampleStaticAnalysis(Visualizer):
    @classmethod
    def update(cls) -> bool:
        pass

    # --- Page 1: Overview & Hash Lookups ---

    @visualizable_error_handler_with_params("File Info")
    def _file_info(self):
        try:
            analyzer_report = self.get_analyzer_reports().get(config__name="File_Info")
        except AnalyzerReport.DoesNotExist:
            logger.warning("File_Info report does not exist")
            return self.Title(
                self.Base(value="File Info", icon=VisualizableIcon.INFO),
                self.Base(value=""),
                disable=True,
            )
        else:
            report = analyzer_report.report
            mimetype = report.get("mimetype", "")
            disabled = analyzer_report.status != ReportStatus.SUCCESS
            return self.Title(
                self.Base(value="File Info", icon=VisualizableIcon.INFO),
                self.Base(value=mimetype or ""),
                disable=disabled,
            )

    @visualizable_error_handler_with_params("Cymru Hash")
    def _cymru_hash(self):
        try:
            analyzer_report = self.get_analyzer_reports().get(config__name="Cymru_Hash_Registry_Get_File")
        except AnalyzerReport.DoesNotExist:
            logger.warning("Cymru_Hash_Registry_Get_File report does not exist")
            return self.Bool(
                value="Cymru Hash",
                disable=True,
            )
        else:
            detected = analyzer_report.report.get("detected", False)
            disabled = analyzer_report.status != ReportStatus.SUCCESS
            return self.Bool(
                value="Cymru Hash",
                disable=not (not disabled and detected),
            )

    @visualizable_error_handler_with_params("HybridAnalysis")
    def _hybrid_analysis(self):
        try:
            analyzer_report = self.get_analyzer_reports().get(config__name="HybridAnalysis_Get_File")
        except AnalyzerReport.DoesNotExist:
            logger.warning("HybridAnalysis_Get_File report does not exist")
            return self.Title(
                self.Base(
                    value="HybridAnalysis",
                    icon=VisualizableIcon.HYBRIDAnalysis,
                ),
                self.Base(value="not available"),
                disable=True,
            )
        else:
            report = analyzer_report.report
            disabled = analyzer_report.status != ReportStatus.SUCCESS
            found = bool(report) and report != {} and report != []
            return self.Title(
                self.Base(
                    value="HybridAnalysis",
                    icon=VisualizableIcon.HYBRIDAnalysis,
                ),
                self.Base(value="found" if found else "not found"),
                disable=disabled or not found,
            )

    @visualizable_error_handler_with_params("MalwareBazaar")
    def _malware_bazaar(self):
        try:
            analyzer_report = self.get_analyzer_reports().get(config__name="MalwareBazaar_Get_File")
        except AnalyzerReport.DoesNotExist:
            logger.warning("MalwareBazaar_Get_File report does not exist")
            return self.Title(
                self.Base(value="MalwareBazaar", icon=VisualizableIcon.MALWARE),
                self.Base(value="not available"),
                disable=True,
            )
        else:
            report = analyzer_report.report
            disabled = analyzer_report.status != ReportStatus.SUCCESS
            query_status = report.get("query_status", "")
            found = query_status == "ok"
            return self.Title(
                self.Base(value="MalwareBazaar", icon=VisualizableIcon.MALWARE),
                self.Base(value="found" if found else "not found"),
                disable=disabled or not found,
            )

    @visualizable_error_handler_with_params("OTX Check Hash")
    def _otx_check_hash(self):
        try:
            analyzer_report = self.get_analyzer_reports().get(config__name="OTX_Check_Hash")
        except AnalyzerReport.DoesNotExist:
            logger.warning("OTX_Check_Hash report does not exist")
            return self.Title(
                self.Base(
                    value="OTX Check Hash",
                    icon=VisualizableIcon.OTX,
                ),
                self.Base(value="not available"),
                disable=True,
            )
        else:
            report = analyzer_report.report
            disabled = analyzer_report.status != ReportStatus.SUCCESS
            pulses = report.get("pulse_info", {}).get("pulses", [])
            found = len(pulses) > 0
            return self.Title(
                self.Base(
                    value="OTX Check Hash",
                    icon=VisualizableIcon.OTX,
                ),
                self.Base(
                    value=f"{len(pulses)} pulse(s)" if found else "not found",
                ),
                disable=disabled or not found,
            )

    @visualizable_error_handler_with_params("HashLookup")
    def _hashlookup(self):
        try:
            analyzer_report = self.get_analyzer_reports().get(config__name="HashLookupServer_Get_File")
        except AnalyzerReport.DoesNotExist:
            logger.warning("HashLookupServer_Get_File report does not exist")
            return self.Title(
                self.Base(value="HashLookup"),
                self.Base(value="not available"),
                disable=True,
            )
        else:
            report = analyzer_report.report
            disabled = analyzer_report.status != ReportStatus.SUCCESS
            found = bool(report) and report != {} and "Not Found" not in str(report)
            return self.Title(
                self.Base(value="HashLookup"),
                self.Base(value="found" if found else "not found"),
                disable=disabled or not found,
            )

    @visualizable_error_handler_with_params("YARAify")
    def _yaraify(self):
        try:
            analyzer_report = self.get_analyzer_reports().get(config__name="YARAify_File_Search")
        except AnalyzerReport.DoesNotExist:
            logger.warning("YARAify_File_Search report does not exist")
            return self.Title(
                self.Base(value="YARAify"),
                self.Base(value="not available"),
                disable=True,
            )
        else:
            report = analyzer_report.report
            disabled = analyzer_report.status != ReportStatus.SUCCESS
            query_status = report.get("query_status", "")
            found = query_status == "ok"
            return self.Title(
                self.Base(value="YARAify"),
                self.Base(value="found" if found else "not found"),
                disable=disabled or not found,
            )

    # --- Page 2: Binary & Document Analysis ---

    @visualizable_error_handler_with_params("PE Info", "Sections")
    def _pe_info(self):
        try:
            analyzer_report = self.get_analyzer_reports().get(config__name="PE_Info")
        except AnalyzerReport.DoesNotExist:
            logger.warning("PE_Info report does not exist")
            pe_title = self.Title(
                self.Base(value="PE Info", icon=VisualizableIcon.INFO),
                self.Base(value=""),
                disable=True,
            )
            pe_sections = self.VList(
                name=self.Base(value="Sections", disable=True),
                value=[],
                start_open=False,
                max_elements_number=10,
                disable=True,
            )
            return pe_title, pe_sections
        else:
            report = analyzer_report.report
            disabled = analyzer_report.status != ReportStatus.SUCCESS
            machine = report.get("machine_type", "")
            sections = report.get("sections", [])
            section_names = [s.get("name", "") for s in sections if s.get("name")]
            pe_title = self.Title(
                self.Base(value="PE Info", icon=VisualizableIcon.INFO),
                self.Base(value=machine or "PE"),
                disable=disabled,
            )
            pe_sections = self.VList(
                name=self.Base(
                    value="Sections",
                    disable=disabled or not section_names,
                ),
                value=[self.Base(value=name, disable=disabled) for name in section_names],
                start_open=False,
                max_elements_number=10,
                report=analyzer_report,
                disable=disabled or not section_names,
            )
            return pe_title, pe_sections

    @visualizable_error_handler_with_params("ELF Info")
    def _elf_info(self):
        try:
            analyzer_report = self.get_analyzer_reports().get(config__name="ELF_Info")
        except AnalyzerReport.DoesNotExist:
            logger.warning("ELF_Info report does not exist")
            return self.Title(
                self.Base(value="ELF Info", icon=VisualizableIcon.INFO),
                self.Base(value=""),
                disable=True,
            )
        else:
            report = analyzer_report.report
            disabled = analyzer_report.status != ReportStatus.SUCCESS
            arch = report.get("arch", "")
            elf_type = report.get("type", "")
            return self.Title(
                self.Base(value="ELF Info", icon=VisualizableIcon.INFO),
                self.Base(value=f"{elf_type} ({arch})" if arch else elf_type or "ELF"),
                disable=disabled,
            )

    @visualizable_error_handler_with_params("APKiD")
    def _apkid(self):
        try:
            analyzer_report = self.get_analyzer_reports().get(config__name="APKiD")
        except AnalyzerReport.DoesNotExist:
            logger.warning("APKiD report does not exist")
            return self.VList(
                name=self.Base(value="APKiD", disable=True),
                value=[],
                start_open=False,
                max_elements_number=5,
                disable=True,
            )
        else:
            report = analyzer_report.report
            disabled = analyzer_report.status != ReportStatus.SUCCESS
            found = bool(report) and report != {}
            detections = []
            if isinstance(report, dict):
                for _, rules in report.items():
                    if isinstance(rules, dict):
                        for rule_type, matches in rules.items():
                            if isinstance(matches, list):
                                for m in matches:
                                    detections.append(f"{rule_type}: {m}")
            return self.VList(
                name=self.Base(
                    value="APKiD",
                    disable=disabled or not found,
                ),
                value=[self.Base(value=d, disable=disabled) for d in detections[:10]],
                start_open=False,
                max_elements_number=5,
                report=analyzer_report,
                disable=disabled or not found,
            )

    @visualizable_error_handler_with_params("GoReSym")
    def _goresym(self):
        try:
            analyzer_report = self.get_analyzer_reports().get(config__name="GoReSym")
        except AnalyzerReport.DoesNotExist:
            logger.warning("GoReSym report does not exist")
            return self.Title(
                self.Base(value="GoReSym"),
                self.Base(value=""),
                disable=True,
            )
        else:
            report = analyzer_report.report
            disabled = analyzer_report.status != ReportStatus.SUCCESS
            found = bool(report) and report != {}
            build_info = ""
            if isinstance(report, dict):
                build_info = report.get("BuildInfo", {})
                if isinstance(build_info, dict):
                    build_info = build_info.get("GoVersion", "")
            return self.Title(
                self.Base(value="GoReSym"),
                self.Base(value=build_info if build_info else "analyzed"),
                disable=disabled or not found,
            )

    @visualizable_error_handler_with_params("Doc Info")
    def _doc_info(self):
        try:
            analyzer_report = self.get_analyzer_reports().get(config__name="Doc_Info")
        except AnalyzerReport.DoesNotExist:
            logger.warning("Doc_Info report does not exist")
            return self.Title(
                self.Base(value="Doc Info", icon=VisualizableIcon.INFO),
                self.Base(value=""),
                disable=True,
            )
        else:
            report = analyzer_report.report
            disabled = analyzer_report.status != ReportStatus.SUCCESS
            found = bool(report) and report != {}
            macros = []
            if isinstance(report, dict):
                macros = report.get("macros", [])
            has_macros = bool(macros)
            return self.Title(
                self.Base(
                    value="Doc Info",
                    icon=(VisualizableIcon.WARNING if has_macros else VisualizableIcon.INFO),
                    color=(VisualizableColor.DANGER if has_macros else VisualizableColor.INFO),
                ),
                self.Base(value="macros detected" if has_macros else "clean"),
                disable=disabled or not found,
            )

    @visualizable_error_handler_with_params("PDF Info")
    def _pdf_info(self):
        try:
            analyzer_report = self.get_analyzer_reports().get(config__name="PDF_Info")
        except AnalyzerReport.DoesNotExist:
            logger.warning("PDF_Info report does not exist")
            return self.Title(
                self.Base(value="PDF Info", icon=VisualizableIcon.INFO),
                self.Base(value=""),
                disable=True,
            )
        else:
            report = analyzer_report.report
            disabled = analyzer_report.status != ReportStatus.SUCCESS
            found = bool(report) and report != {}
            # Check for suspicious elements
            suspicious = False
            if isinstance(report, dict):
                for key in ["js", "javascript", "openaction", "launch"]:
                    if report.get(key, 0):
                        suspicious = True
                        break
            return self.Title(
                self.Base(
                    value="PDF Info",
                    icon=(VisualizableIcon.WARNING if suspicious else VisualizableIcon.INFO),
                    color=(VisualizableColor.DANGER if suspicious else VisualizableColor.INFO),
                ),
                self.Base(value="suspicious" if suspicious else "clean"),
                disable=disabled or not found,
            )

    @visualizable_error_handler_with_params("OneNote Info")
    def _onenote_info(self):
        try:
            analyzer_report = self.get_analyzer_reports().get(config__name="OneNote_Info")
        except AnalyzerReport.DoesNotExist:
            logger.warning("OneNote_Info report does not exist")
            return self.Title(
                self.Base(value="OneNote Info"),
                self.Base(value=""),
                disable=True,
            )
        else:
            report = analyzer_report.report
            disabled = analyzer_report.status != ReportStatus.SUCCESS
            found = bool(report) and report != {}
            return self.Title(
                self.Base(value="OneNote Info"),
                self.Base(value="analyzed" if found else ""),
                disable=disabled or not found,
            )

    @visualizable_error_handler_with_params("RTF Info")
    def _rtf_info(self):
        try:
            analyzer_report = self.get_analyzer_reports().get(config__name="Rtf_Info")
        except AnalyzerReport.DoesNotExist:
            logger.warning("Rtf_Info report does not exist")
            return self.Title(
                self.Base(value="RTF Info"),
                self.Base(value=""),
                disable=True,
            )
        else:
            report = analyzer_report.report
            disabled = analyzer_report.status != ReportStatus.SUCCESS
            found = bool(report) and report != {}
            return self.Title(
                self.Base(value="RTF Info"),
                self.Base(value="analyzed" if found else ""),
                disable=disabled or not found,
            )

    @visualizable_error_handler_with_params("XLM Macro")
    def _xlm_macro(self):
        try:
            analyzer_report = self.get_analyzer_reports().get(config__name="Xlm_Macro_Deobfuscator")
        except AnalyzerReport.DoesNotExist:
            logger.warning("Xlm_Macro_Deobfuscator report does not exist")
            return self.Title(
                self.Base(value="XLM Macro"),
                self.Base(value=""),
                disable=True,
            )
        else:
            report = analyzer_report.report
            disabled = analyzer_report.status != ReportStatus.SUCCESS
            found = bool(report) and report != {}
            return self.Title(
                self.Base(
                    value="XLM Macro",
                    icon=(VisualizableIcon.WARNING if found else VisualizableIcon.EMPTY),
                    color=(VisualizableColor.DANGER if found else VisualizableColor.INFO),
                ),
                self.Base(value="macros found" if found else ""),
                disable=disabled or not found,
            )

    # --- Page 3: Signatures & Rules ---

    @visualizable_error_handler_with_params("Yara", "Yara Signatures")
    def _yara(self):
        try:
            analyzer_report = self.get_analyzer_reports().get(config__name="Yara")
        except AnalyzerReport.DoesNotExist:
            logger.warning("Yara report does not exist")
            yara_title = self.Title(
                self.Base(
                    value="Yara",
                    icon=VisualizableIcon.SHIELD,
                ),
                self.Base(value=""),
                disable=True,
            )
            yara_sigs = self.VList(
                name=self.Base(value="Yara Signatures", disable=True),
                value=[],
                start_open=False,
                max_elements_number=10,
                disable=True,
            )
            return yara_title, yara_sigs
        else:
            report = analyzer_report.report
            disabled = analyzer_report.status != ReportStatus.SUCCESS
            num_matches = sum(len(matches) for matches in report.values())
            signatures = [
                match.get("match", "")
                for matches in report.values()
                for match in matches
                if match.get("match")
            ]
            yara_title = self.Title(
                self.Base(
                    value="Yara",
                    icon=VisualizableIcon.SHIELD,
                    color=(VisualizableColor.DANGER if num_matches else VisualizableColor.INFO),
                ),
                self.Base(value=f"{num_matches} match(es)"),
                disable=disabled or not num_matches,
            )
            yara_sigs = self.VList(
                name=self.Base(
                    value="Yara Signatures",
                    disable=disabled or not signatures,
                ),
                value=[self.Base(value=sig, disable=disabled) for sig in signatures],
                start_open=False,
                max_elements_number=10,
                report=analyzer_report,
                disable=disabled or not signatures,
            )
            return yara_title, yara_sigs

    @visualizable_error_handler_with_params("Signature Info")
    def _signature_info(self):
        try:
            analyzer_report = self.get_analyzer_reports().get(config__name="Signature_Info")
        except AnalyzerReport.DoesNotExist:
            logger.warning("Signature_Info report does not exist")
            return self.Title(
                self.Base(
                    value="Signature Info",
                    icon=VisualizableIcon.SHIELD,
                ),
                self.Base(value=""),
                disable=True,
            )
        else:
            report = analyzer_report.report
            disabled = analyzer_report.status != ReportStatus.SUCCESS
            found = bool(report) and report != {}
            return self.Title(
                self.Base(
                    value="Signature Info",
                    icon=VisualizableIcon.SHIELD,
                ),
                self.Base(value="signed" if found else "not signed"),
                disable=disabled,
            )

    @visualizable_error_handler_with_params("ClamAV", "ClamAV Rules")
    def _clamav(self):
        try:
            analyzer_report = self.get_analyzer_reports().get(config__name="ClamAV")
        except AnalyzerReport.DoesNotExist:
            logger.warning("ClamAV report does not exist")
            clamav_title = self.Title(
                self.Base(
                    value="ClamAV",
                    icon=VisualizableIcon.SHIELD,
                ),
                self.Base(value=""),
                disable=True,
            )
            clamav_rules = self.VList(
                name=self.Base(value="ClamAV Rules", disable=True),
                value=[],
                start_open=False,
                max_elements_number=10,
                disable=True,
            )
            return clamav_title, clamav_rules
        else:
            report = analyzer_report.report
            disabled = analyzer_report.status != ReportStatus.SUCCESS
            malicious = False
            detections = []
            if isinstance(report, dict):
                malicious = report.get("is_infected", False)
                detections = report.get("detections", [])
                if not isinstance(detections, list):
                    detections = [detections] if detections else []
            clamav_title = self.Title(
                self.Base(
                    value="ClamAV",
                    icon=(VisualizableIcon.MALWARE if malicious else VisualizableIcon.SHIELD),
                    color=(VisualizableColor.DANGER if malicious else VisualizableColor.SUCCESS),
                ),
                self.Base(value=f"{len(detections)} detection(s)" if detections else "clean"),
                disable=disabled,
            )
            clamav_rules = self.VList(
                name=self.Base(
                    value="ClamAV Rules",
                    disable=disabled or not detections,
                ),
                value=[
                    self.Base(
                        value=d if isinstance(d, str) else str(d),
                        disable=disabled,
                    )
                    for d in detections
                ],
                start_open=False,
                max_elements_number=10,
                report=analyzer_report,
                disable=disabled or not detections,
            )
            return clamav_title, clamav_rules

    @visualizable_error_handler_with_params("Quark Engine", "Quark Rules")
    def _quark_engine(self):
        try:
            analyzer_report = self.get_analyzer_reports().get(config__name="Quark_Engine")
        except AnalyzerReport.DoesNotExist:
            logger.warning("Quark_Engine report does not exist")
            quark_title = self.Title(
                self.Base(value="Quark Engine"),
                self.Base(value=""),
                disable=True,
            )
            quark_rules = self.VList(
                name=self.Base(value="Quark Rules", disable=True),
                value=[],
                start_open=False,
                max_elements_number=10,
                disable=True,
            )
            return quark_title, quark_rules
        else:
            report = analyzer_report.report
            disabled = analyzer_report.status != ReportStatus.SUCCESS
            found = bool(report) and report != {}
            threat_level = ""
            crimes = []
            if isinstance(report, dict):
                threat_level = report.get("threat_level", "")
                crimes_list = report.get("crimes", [])
                if isinstance(crimes_list, list):
                    for crime in crimes_list:
                        if isinstance(crime, dict):
                            desc = crime.get("crime", "")
                            if desc:
                                crimes.append(desc)
                        elif isinstance(crime, str):
                            crimes.append(crime)
            quark_title = self.Title(
                self.Base(value="Quark Engine"),
                self.Base(value=threat_level if threat_level else "analyzed"),
                disable=disabled or not found,
            )
            quark_rules = self.VList(
                name=self.Base(
                    value="Quark Rules",
                    disable=disabled or not crimes,
                ),
                value=[self.Base(value=crime, disable=disabled) for crime in crimes],
                start_open=False,
                max_elements_number=10,
                report=analyzer_report,
                disable=disabled or not crimes,
            )
            return quark_title, quark_rules

    @visualizable_error_handler_with_params("Capa", "Capa Capabilities")
    def _capa_info(self):
        try:
            analyzer_report = self.get_analyzer_reports().get(config__name="Capa_Info")
        except AnalyzerReport.DoesNotExist:
            logger.warning("Capa_Info report does not exist")
            capa_title = self.Title(
                self.Base(
                    value="Capa",
                    icon=VisualizableIcon.MAGNIFYING_GLASS,
                ),
                self.Base(value=""),
                disable=True,
            )
            capa_list = self.VList(
                name=self.Base(value="Capa Capabilities", disable=True),
                value=[],
                start_open=False,
                max_elements_number=10,
                disable=True,
            )
            return capa_title, capa_list
        else:
            report = analyzer_report.report
            disabled = analyzer_report.status != ReportStatus.SUCCESS
            capabilities = []
            if isinstance(report, dict):
                rules = report.get("rules", {})
                if isinstance(rules, dict):
                    capabilities = list(rules.keys())
            num_caps = len(capabilities)
            capa_title = self.Title(
                self.Base(
                    value="Capa",
                    icon=VisualizableIcon.MAGNIFYING_GLASS,
                    color=(VisualizableColor.DANGER if num_caps else VisualizableColor.INFO),
                ),
                self.Base(value=f"{num_caps} capability(ies)"),
                disable=disabled or not num_caps,
            )
            capa_list = self.VList(
                name=self.Base(
                    value="Capa Capabilities",
                    disable=disabled or not capabilities,
                ),
                value=[self.Base(value=cap, disable=disabled) for cap in capabilities[:20]],
                start_open=False,
                max_elements_number=10,
                report=analyzer_report,
                disable=disabled or not capabilities,
            )
            return capa_title, capa_list

    @visualizable_error_handler_with_params("BoxJS")
    def _boxjs(self):
        try:
            analyzer_report = self.get_analyzer_reports().get(config__name="BoxJS")
        except AnalyzerReport.DoesNotExist:
            logger.warning("BoxJS report does not exist")
            return self.VList(
                name=self.Base(
                    value="BoxJS URLs",
                    disable=True,
                ),
                value=[],
                start_open=False,
                max_elements_number=5,
                disable=True,
            )
        else:
            report = analyzer_report.report
            disabled = analyzer_report.status != ReportStatus.SUCCESS
            found = bool(report) and report != {}
            urls = []
            if isinstance(report, dict):
                urls = report.get("urls", [])
            return self.VList(
                name=self.Base(
                    value="BoxJS URLs",
                    icon=(VisualizableIcon.WARNING if urls else VisualizableIcon.EMPTY),
                    color=(VisualizableColor.DANGER if urls else VisualizableColor.INFO),
                    disable=disabled or not found,
                ),
                value=[self.Base(value=url, disable=disabled) for url in urls[:10]],
                start_open=False,
                max_elements_number=5,
                report=analyzer_report,
                disable=disabled or not found,
            )

    # --- run ---

    def run(self) -> List[Dict]:
        # --- Page 1: Overview & Hash Lookups ---
        page1 = self.Page(name="Overview")

        hash_lookup_elements = [
            self._cymru_hash(),
            self._hybrid_analysis(),
            self._malware_bazaar(),
            self._otx_check_hash(),
            self._hashlookup(),
            self._yaraify(),
        ]
        page1.add_level(
            self.Level(
                position=1,
                size=self.LevelSize.S_5,
                horizontal_list=self.HList(value=hash_lookup_elements),
            )
        )

        # --- Page 2: Binary & Document Analysis ---
        page2 = self.Page(name="Binary & Document Analysis")

        # Row 1: Summary titles
        binary_summary = []
        # Row 2: Detailed lists
        binary_lists = []

        pe_result = self._pe_info()
        if isinstance(pe_result, tuple | list):
            binary_summary.append(pe_result[0])  # pe_title
            binary_lists.append(pe_result[1])  # pe_sections
        elif pe_result:
            binary_summary.append(pe_result)

        binary_summary.append(self._elf_info())
        binary_summary.append(self._goresym())

        # APKiD returns a VList (can be long) — goes to lists row
        binary_lists.append(self._apkid())

        # Doc analysis titles — also in summary row
        binary_summary.extend(
            [
                self._doc_info(),
                self._pdf_info(),
                self._onenote_info(),
                self._rtf_info(),
                self._xlm_macro(),
            ]
        )

        page2.add_level(
            self.Level(
                position=1,
                size=self.LevelSize.S_3,
                horizontal_list=self.HList(value=binary_summary),
            )
        )
        page2.add_level(
            self.Level(
                position=2,
                size=self.LevelSize.S_5,
                horizontal_list=self.HList(value=binary_lists),
            )
        )

        # --- Page 3: Signatures & Rules ---
        page3 = self.Page(name="Signatures & Rules")

        # Row 1: Match counts (summary)
        sig_summary = []
        # Row 2: Detailed signature lists
        sig_lists = []

        yara_result = self._yara()
        if isinstance(yara_result, tuple | list):
            sig_summary.append(yara_result[0])  # yara_title (count)
            sig_lists.append(yara_result[1])  # yara_sigs (list)
        elif yara_result:
            sig_summary.append(yara_result)

        sig_summary.append(self._signature_info())

        clamav_result = self._clamav()
        if isinstance(clamav_result, tuple | list):
            sig_summary.append(clamav_result[0])  # clamav_title (count)
            sig_lists.append(clamav_result[1])  # clamav_rules (list)
        elif clamav_result:
            sig_summary.append(clamav_result)

        quark_result = self._quark_engine()
        if isinstance(quark_result, tuple | list):
            sig_summary.append(quark_result[0])  # quark_title (count)
            sig_lists.append(quark_result[1])  # quark_rules (list)
        elif quark_result:
            sig_summary.append(quark_result)

        capa_result = self._capa_info()
        if isinstance(capa_result, tuple | list):
            sig_summary.append(capa_result[0])  # capa_title (count)
            sig_lists.append(capa_result[1])  # capa_list (capabilities)
        elif capa_result:
            sig_summary.append(capa_result)

        page3.add_level(
            self.Level(
                position=1,
                size=self.LevelSize.S_3,
                horizontal_list=self.HList(value=sig_summary),
            )
        )
        page3.add_level(
            self.Level(
                position=2,
                size=self.LevelSize.S_5,
                horizontal_list=self.HList(value=sig_lists),
            )
        )

        additional_elements = [
            self._boxjs(),
        ]
        page3.add_level(
            self.Level(
                position=3,
                size=self.LevelSize.S_5,
                horizontal_list=self.HList(value=additional_elements),
            )
        )

        logger.debug(f"page1: {page1.to_dict()}")
        logger.debug(f"page2: {page2.to_dict()}")
        logger.debug(f"page3: {page3.to_dict()}")
        return [page1.to_dict(), page2.to_dict(), page3.to_dict()]

    @classmethod
    def _monkeypatch(cls):
        patches = []
        return super()._monkeypatch(patches=patches)
