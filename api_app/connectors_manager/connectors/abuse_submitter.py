from api_app.connectors_manager.connectors.email_sender import EmailSender
from api_app.connectors_manager.exceptions import ConnectorRunException


class AbuseSubmitter(EmailSender):
    def _validate_job_hierarchy(self):
        if not (self._job.parent_job and self._job.parent_job.parent_job):
            raise ConnectorRunException(
                "Job hierarchy is invalid. This connector requires a 'Job -> Parent -> Grandparent' structure. "
                "Ensure it's run within the 'Takedown_Request' playbook."
            )

    @property
    def subject(self) -> str:
        self._validate_job_hierarchy()
        return f"Takedown domain request for {self._job.parent_job.parent_job.analyzable.name}"

    @property
    def body(self) -> str:
        self._validate_job_hierarchy()
        return (
            f"Domain {self._job.parent_job.parent_job.analyzable.name} "
            "has been detected as malicious by our team. We kindly request you to take "
            "it down as soon as possible."
        )
