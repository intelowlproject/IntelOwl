from api_app.connectors_manager.connectors.email_sender import EmailSender


class AbuseSubmitter(EmailSender):
    @property
    def subject(self) -> str:
        return f"Takedown domain request for {self._job.parent_job.parent_job.observable_name}"

    @property
    def body(self) -> str:
        return (
            f"Domain {self._job.parent_job.parent_job.observable_name} "
            "has been reported as malicious. We request you to take it down."
        )
