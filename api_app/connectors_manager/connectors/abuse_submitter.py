from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.connectors_manager.connectors.email_sender import EmailSender


class AbuseSubmitter(EmailSender):
    @property
    def subject(self) -> str:
        return (
            "Takedown domain request for "
            f"{self._job.parent_job.parent_job.observable_name}"
        )

    @property
    def body(self) -> str:
        if not self._job.parent_job:
            raise AnalyzerRunException(
                "Parent job does not exist. "
                "This analyzer must be run only with the playbook Takedown_Request to work properly"
            )
        return (
            f"Domain {self._job.parent_job.parent_job.observable_name} "
            "has been detected as malicious by our team. We kindly request you to take "
            "it down as soon as possible."
        )
