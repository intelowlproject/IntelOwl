from logging import getLogger
from typing import Dict, List

# ignore flake line too long in imports
from api_app.analyzers_manager.models import AnalyzerReport
from api_app.analyzers_manager.observable_analyzers.download_file_from_uri import (
    DownloadFileFromUri,
)
from api_app.analyzers_manager.observable_analyzers.vt.vt3_sample_download import (
    VirusTotalv3SampleDownload,
)
from api_app.visualizers_manager.classes import (
    VisualizableBase,
    VisualizableDownload,
    VisualizableVerticalList,
    Visualizer,
)
from api_app.visualizers_manager.decorators import (
    visualizable_error_handler_with_params,
)

logger = getLogger(__name__)


class SampleDownload(Visualizer):

    @visualizable_error_handler_with_params("VirusTotal")
    def _vt_button(self):
        try:
            vt_report = self.analyzer_reports().get(
                config__python_module=VirusTotalv3SampleDownload.python_module
            )
        except AnalyzerReport.DoesNotExist:
            payload = ""
        else:
            payload = vt_report.report["data"]
        disable = not payload
        return VisualizableDownload(
            value="VirusTotal",
            payload=payload,
            disable=disable,
        )

    @visualizable_error_handler_with_params("URI")
    def _download_uri(self):
        try:
            uri_report = self.analyzer_reports().get(
                config__python_module=DownloadFileFromUri.python_module
            )
        except AnalyzerReport.DoesNotExist:
            base64_file_list = []
        else:
            base64_file_list = uri_report.report["stored_base64"]
        disable_element = not base64_file_list
        return VisualizableVerticalList(
            name=VisualizableBase(value="URI", disable=disable_element),
            value=[
                VisualizableDownload(
                    value=f"Sample-{index + 1}",
                    payload=base64_file,
                )
                for index, base64_file in enumerate(base64_file_list)
            ],
            disable=disable_element,
            start_open=True,
        )

    def run(self) -> List[Dict]:
        page = self.Page(name="Download")
        page.add_level(
            self.Level(
                position=1,
                size=self.LevelSize.S_3,
                horizontal_list=self.HList(
                    value=[
                        self._vt_button(),
                        self._download_uri(),
                    ]
                ),
            )
        )
        logger.debug(f"levels: {page.to_dict()}")
        return [page.to_dict()]

    @classmethod
    def _monkeypatch(cls):
        # TODO
        patches = []
        return super()._monkeypatch(patches=patches)
