import json
from logging import getLogger
from typing import Dict, List

from api_app.analyzers_manager.file_analyzers.phishing.phishing_form_compiler import (
    PhishingFormCompiler,
)
from api_app.analyzers_manager.models import AnalyzerReport
from api_app.analyzers_manager.observable_analyzers.phishing.phishing_extractor import (
    PhishingExtractor,
)
from api_app.visualizers_manager.classes import (
    VisualizableBase,
    VisualizableBool,
    VisualizableDownload,
    VisualizableImage,
    VisualizableVerticalList,
    Visualizer,
)
from api_app.visualizers_manager.decorators import (
    visualizable_error_handler_with_params,
)

logger = getLogger(__name__)


class PhishingAnalysis(Visualizer):
    @classmethod
    def update(cls) -> bool:
        pass

    @visualizable_error_handler_with_params("Screenshot")
    def _screenshot(self):
        try:
            extractor_report = self.get_analyzer_reports().get(
                config__python_module=PhishingExtractor.python_module
            )
        except AnalyzerReport.DoesNotExist:
            return VisualizableBase(value="No screenshot available", disable=True)
        screenshot_base64 = extractor_report.report.get("page_screenshot_base64", "")
        if not screenshot_base64:
            return VisualizableBase(value="No screenshot available", disable=True)
        return VisualizableImage(
            base64=screenshot_base64,
            title="Page Screenshot",
            description="Screenshot captured by PhishingExtractor",
            disable=False,
        )

    @visualizable_error_handler_with_params("Page Source Download")
    def _page_source_download(self):
        try:
            extractor_report = self.get_analyzer_reports().get(
                config__python_module=PhishingExtractor.python_module
            )
        except AnalyzerReport.DoesNotExist:
            return VisualizableBase(value="No page source available", disable=True)
        page_source = extractor_report.report.get("page_source", "")
        disable = not page_source
        return VisualizableDownload(
            value="Page Source",
            payload=page_source,
            disable=disable,
        )

    @visualizable_error_handler_with_params("JavaScript Detection")
    def _javascript_detection(self):
        try:
            form_report = self.get_analyzer_reports().get(
                config__python_module=PhishingFormCompiler.python_module
            )
        except AnalyzerReport.DoesNotExist:
            return VisualizableBase(value="No JavaScript detection data found", disable=True)
        has_js = form_report.report.get("has_javascript", False)
        return VisualizableBool(
            value="JavaScript Detected",
            disable=not has_js,
        )

    @visualizable_error_handler_with_params("Extracted URLs")
    def _extracted_urls(self):
        try:
            form_report = self.get_analyzer_reports().get(
                config__python_module=PhishingFormCompiler.python_module
            )
        except AnalyzerReport.DoesNotExist:
            return VisualizableBase(value="No extracted URLs found", disable=True)
        extracted_urls = form_report.report.get("extracted_urls", [])
        disable = not extracted_urls
        return VisualizableVerticalList(
            name=VisualizableBase(value="Extracted URLs", disable=disable),
            value=[VisualizableBase(value=url, disable=False) for url in extracted_urls],
            disable=disable,
            start_open=True,
        )

    @visualizable_error_handler_with_params("Redirection URLs")
    def _redirection_urls(self):
        try:
            form_report = self.get_analyzer_reports().get(
                config__python_module=PhishingFormCompiler.python_module
            )
        except AnalyzerReport.DoesNotExist:
            return VisualizableBase(value="No redirection URLs found", disable=True)
        redirection_urls = form_report.report.get("redirection_urls", [])
        disable = not redirection_urls
        return VisualizableVerticalList(
            name=VisualizableBase(value="Redirection URLs", disable=disable),
            value=[VisualizableBase(value=url, disable=False) for url in redirection_urls],
            disable=disable,
            start_open=True,
        )

    @visualizable_error_handler_with_params("HTTP Traffic Download")
    def _http_traffic_download(self):
        try:
            extractor_report = self.get_analyzer_reports().get(
                config__python_module=PhishingExtractor.python_module
            )
        except AnalyzerReport.DoesNotExist:
            return VisualizableBase(value="No HTTP traffic data available", disable=True)
        http_traffic = extractor_report.report.get("page_http_traffic", [])
        http_har = extractor_report.report.get("page_http_har", {})
        combined_data = {
            "http_traffic": http_traffic,
            "http_har": http_har,
        }
        payload = json.dumps(combined_data, indent=2, default=str)
        disable = not http_traffic and not http_har
        return VisualizableDownload(
            value="HTTP Traffic",
            payload=payload,
            disable=disable,
        )

    def run(self) -> List[Dict]:
        # Tab 1: Screenshot only
        page_screenshot = self.Page(name="Screenshot")
        page_screenshot.add_level(
            self.Level(
                position=1,
                size=self.LevelSize.S_3,
                horizontal_list=self.HList(value=[self._screenshot()]),
            )
        )

        # Tab 2: Analysis details (source, JS, URLs, HTTP traffic)
        page_details = self.Page(name="Analysis Details")

        # Level 1: Page source download + JS detection
        page_details.add_level(
            self.Level(
                position=1,
                size=self.LevelSize.S_5,
                horizontal_list=self.HList(
                    value=[
                        self._page_source_download(),
                        self._javascript_detection(),
                    ]
                ),
            )
        )

        # Level 2: Extracted URLs + Redirection URLs
        page_details.add_level(
            self.Level(
                position=2,
                size=self.LevelSize.S_3,
                horizontal_list=self.HList(
                    value=[
                        self._extracted_urls(),
                        self._redirection_urls(),
                    ]
                ),
            )
        )

        # Level 3: HTTP Traffic download
        page_details.add_level(
            self.Level(
                position=3,
                size=self.LevelSize.S_3,
                horizontal_list=self.HList(value=[self._http_traffic_download()]),
            )
        )

        logger.debug(f"pages: {page_screenshot.to_dict()}, {page_details.to_dict()}")
        return [page_screenshot.to_dict(), page_details.to_dict()]

    @classmethod
    def _monkeypatch(cls):
        # TODO
        patches = []
        return super()._monkeypatch(patches=patches)
