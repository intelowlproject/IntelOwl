# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from pycti.api.opencti_api_client import File
import pycti

from tests.mock_utils import patch, if_mock_connections
from api_app.analyzers_manager import classes


# for lighter output (credits: Cortex-Analyzers/opencti)
RESULT_TRIM_MAP = {
    "observable": [
        "objectMarkingIds",
        "objectLabelIds",
        "externalReferencesIds",
        "indicatorsIds",
        "parent_types",
    ],
    "report": {
        "objects",
        "objectMarkingIds",
        "externalReferencesIds",
        "objectLabelIds",
        "parent_types",
        "objectsIds",
        "x_opencti_graph_data",
    },
}


class OpenCTI(classes.ObservableAnalyzer):
    def set_params(self, params):
        self.ssl_verify = params.get("ssl_verify", True)
        self.proxies = params.get("proxies", {})
        self.exact_search = params.get("exact_search", False)
        self.__url_name = self._secrets["url_key_name"]
        self.__api_key = self._secrets["api_key_name"]

    def run(self):
        # set up client
        opencti_instance = pycti.OpenCTIApiClient(
            url=self.__url_name,
            token=self.__api_key,
            ssl_verify=self.ssl_verify,
            proxies=self.proxies,
        )

        # search for observables
        observables = pycti.StixCyberObservable(opencti_instance, File).list(
            search=self._job.observable_name
        )

        # Filter exact matches if exact_search is set
        if self.exact_search:
            observables = [
                obs
                for obs in observables
                if obs["observable_value"] == self._job.observable_name
            ]

        for observable in observables:
            # get reports linked to this observable
            reports = pycti.Report(opencti_instance).list(
                filters=[
                    {
                        "key": "objectContains",
                        "values": [observable["id"]],
                    }
                ]
            )
            # trim observable data
            for key in RESULT_TRIM_MAP["observable"]:
                observable.pop(key, None)
            for report in reports:
                # trim report data
                for key in RESULT_TRIM_MAP["report"]:
                    report.pop(key, None)

            observable["reports"] = reports

        return observables

    @classmethod
    def _monkeypatch(cls):
        mock_result = [{"id": 1, "observable_value": "8.8.8.8"}]

        patches = [
            if_mock_connections(
                patch("pycti.OpenCTIApiClient", return_value=None),
                patch("pycti.StixCyberObservable.list", return_value=mock_result),
                patch("pycti.Report.list", return_value=mock_result),
            )
        ]
        return super()._monkeypatch(patches=patches)
