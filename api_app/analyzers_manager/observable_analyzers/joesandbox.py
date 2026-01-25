import logging

from jbxapi import JoeSandbox

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.mixins import JoeSandboxMixin

logger = logging.getLogger(__name__)


class JoeSandboxAnalyzer(ObservableAnalyzer, JoeSandboxMixin):

    sample_at_url: bool = False

    @classmethod
    def update(cls):
        pass

    def run(self):
        sandbox_session = JoeSandbox(
            apikey=self._api_key, apiurl=self.url, accept_tac=True
        )

        if not self.force_new_analysis:
            # checking if existing analysis is present and returns the results
            existing_results = self.fetch_existing_results_if_present(
                sandbox_session=sandbox_session,
                observable_name=self.observable_name,
                observable_url=self.observable_name,
            )

            if existing_results:
                return existing_results

        # creating new analysis, if no existing analysis is present
        submission_id = self.create_new_analysis(
            sandbox_session=sandbox_session,
            observable_url=self.observable_name,
            sample_at_url=self.sample_at_url,
        )
        results = self.fetch_results(
            sandbox_session=sandbox_session,
            submission_id=submission_id,
            observable_name=self.observable_name,
        )

        return results
