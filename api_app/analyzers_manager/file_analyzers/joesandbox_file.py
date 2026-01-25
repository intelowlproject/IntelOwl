import logging

from jbxapi import JoeSandbox

from api_app.analyzers_manager.classes import FileAnalyzer
from api_app.mixins import JoeSandboxMixin

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
