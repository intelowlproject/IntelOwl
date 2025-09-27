import logging

from jbxapi import JoeSandbox

from api_app.analyzers_manager.classes import FileAnalyzer
from api_app.mixins import JoeSandboxMixin
from tests.mock_utils import if_mock_connections, patch

logger = logging.getLogger(__name__)


class JoeSandboxFile(FileAnalyzer, JoeSandboxMixin):

    @classmethod
    def update(cls):
        pass

    def run(self):
        sandbox_session = JoeSandbox(
            apiurl=self.url, apikey=self._api_key, accept_tac=True
        )
        sample_file = self._job.analyzable.file

        if not self.force_new_analysis:
            # checking if existing analysis is present and returns the results
            existing_results = self.fetch_existing_results_if_present(
                sandbox_session=sandbox_session,
                observable_name=self.filename,
                file_hash=self.md5,
            )

            if existing_results:
                return existing_results

        # submit new sample if no existing analysis is present
        file_details = (self.filename, sample_file)

        submission_id = self.create_new_analysis(
            sandbox_session=sandbox_session, file_details=file_details
        )
        results = self.fetch_results(
            sandbox_session=sandbox_session,
            submission_id=submission_id,
            observable_name=self.filename,
        )

        return results

    @classmethod
    def _monkeypatch(cls):

        analysis_info_response = {
            "webid": "100",
            "analysisid": "4",
            "status": "finished",
            "detection": "malicious",
            "score": 42,
            "classification": "",
            "threatname": "Unknown",
            "comments": "a sample comment",
            "filename": "sample.exe",
            "scriptname": "default.jbs",
            "time": "2017-08-11T16:06:32+02:00",
            "duration": 150,
            "encrypted": False,
            "md5": "0cbc6611f5540bd0809a388dc95a615b",
            "sha1": "640ab2bae07bedc4c163f679a746f7ab7fb5d1fa",
            "sha256": "532eaabd9574880 [...] 299550d7a6e0f345e25",
            "tags": ["internal", "important"],
            # Present while Live Interaction is active
            "live-interaction-url": "https://joesandbox.com/analysis/123456789",
            "runs": [
                {
                    "detection": "unknown",
                    "error": "Unable to run",
                    "system": "w7",
                    "yara": False,
                    "sigma": False,
                    "score": 1,
                },
                {
                    "detection": "malicious",
                    "error": None,
                    "system": "w7x64",
                    "yara": False,
                    "sigma": False,
                    "score": 42,
                },
            ],
        }

        patches = [
            if_mock_connections(
                patch.object(
                    JoeSandboxFile,
                    "fetch_existing_results_if_present",
                    return_value=analysis_info_response,
                ),
                patch.object(
                    JoeSandboxFile, "create_new_analysis", return_value="1008"
                ),
                patch.object(
                    JoeSandboxFile, "fetch_results", return_value=analysis_info_response
                ),
            )
        ]
        return super()._monkeypatch(patches)
