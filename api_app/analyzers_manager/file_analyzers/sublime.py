import base64
import email
from email.message import Message
from logging import getLogger
from typing import Dict

import requests
from django.utils.functional import cached_property

from api_app.analyzers_manager.classes import FileAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.analyzers_manager.models import MimeTypes

logger = getLogger(__name__)


class Sublime(FileAnalyzer):
    _api_key: str
    _message_source_id: str
    _url: str
    analyze_internal_eml_on_pec: bool
    headers = {"accept": "application/json", "content-type": "application/json"}
    live_flow_endpoint = "/v1/live-flow/raw-messages/analyze"
    retrieve_message_endpoint = "/v0/messages"
    api_port = 8000
    gui_port = 3000

    def config(self, runtime_configuration: Dict):
        super().config(runtime_configuration)
        if self._url.endswith("/"):
            self._url = self._url[:-1]

    @cached_property
    def email(self) -> Message:
        return email.message_from_bytes(self.read_file_bytes())

    def is_pec(self) -> bool:
        found_eml, found_signature, found_xml = False, False, False
        payload = self.email.get_payload()
        if isinstance(payload, str):
            return False
        for attachment in payload:
            attachment: Message
            content_type = attachment.get_content_type()
            filename = attachment.get_filename()
            logger.debug(f"{content_type=} {filename=} ")
            if content_type == MimeTypes.MIXED.value:
                for internal_attachment in attachment.get_payload():
                    internal_attachment: Message
                    internal_attachment_content = internal_attachment.get_content_type()
                    internal_attachment_name = internal_attachment.get_filename()
                    logger.debug(f"{internal_attachment_name=} {internal_attachment_content=} ")
                    if (
                        internal_attachment_content == MimeTypes.EML.value
                        and internal_attachment_name == "postacert.eml"
                    ):
                        self._real_email = attachment.get_payload(0).as_bytes()
                        found_eml = True
                    elif (
                        internal_attachment_content in [MimeTypes.XML1.value, MimeTypes.XML2.value]
                        and internal_attachment_name == "daticert.xml"
                    ):
                        found_xml = True
            elif content_type in [MimeTypes.PKCS7.value, MimeTypes.XPKCS7.value] and filename == "smime.p7s":
                found_signature = True
        logger.debug(f"{found_xml=} {found_eml=} {found_signature=}")
        return found_eml and found_signature and found_xml

    @property
    def raw_message(self) -> str:
        if self.file_mimetype == MimeTypes.OUTLOOK.value:
            import subprocess
            import tempfile

            with tempfile.NamedTemporaryFile() as file:
                command = ["msgconvert", file.name, "--outfile", "-"]
                file.seek(0)
                file.write(self.read_file_bytes())
                file.seek(0)
                proc = subprocess.run(command, check=True, stdout=subprocess.PIPE)
                return base64.b64encode(proc.stdout.strip()).decode("utf-8")
        return str(base64.b64encode(self._job.analyzable.read()), "utf-8")

    def _analysis(self, session: requests.Session, content: str):
        result = session.post(
            f"{self._url}:{self.api_port}{self.live_flow_endpoint}",
            json={
                "create_mailbox": True,
                "raw_message": content,
                "message_source_id": self._message_source_id,
                "mailbox_email_address": self._job.user.email,
                "labels": [self._job.user.username],
                "run_active_detection_rules": True,
                "run_all_detection_rules": False,
            },
            timeout=50,
        )
        try:
            result.raise_for_status()
        except requests.exceptions.RequestException:
            raise AnalyzerRunException(result.content)
        else:
            result_analysis = result.json()
            logger.info(f"Result is {result_analysis}")
            result_message = session.get(
                f"{self._url}:{self.api_port}{self.retrieve_message_endpoint}/"
                f"{result_analysis['message_id']}",
                timeout=20,
            )
            try:
                result_message.raise_for_status()
            except requests.exceptions.RequestException:
                self.report.errors.append(result_message.content)
                raise AnalyzerRunException(result_message.content)
            else:
                result_message = result_message.json()
                canonical_id = result_message["canonical_id"]
                logger.info(f"{result_message=}")
                return {
                    "flagged_rules": [
                        {
                            key: rule[key]
                            for key in [
                                "name",
                                "description",
                                "severity",
                                "maturity",
                                "label",
                                "tags",
                                "false_positives",
                                "references",
                                "updated_at",
                                "authors",
                            ]
                        }
                        for rule in result_analysis["flagged_rules"]
                    ],
                    "gui_url": f"{self._url}:{self.gui_port}/messages/{canonical_id}",
                    **{key: result_message[key] for key in ["subject", "sender", "recipients", "created_at"]},
                }

    def run(self) -> Dict:
        self.headers["Authorization"] = f"Bearer {self._api_key}"
        session = requests.Session()
        session.headers = self.headers
        report = self._analysis(session, self.raw_message)
        if self.analyze_internal_eml_on_pec and self.file_mimetype == MimeTypes.EML.value and self.is_pec():
            logger.info("Email is a pec")
            report_pec = self._analysis(session, base64.b64encode(self._real_email).decode("utf-8"))
            report["pec"] = report_pec
        return report
