import logging

import phonenumbers
import requests

from api_app.analyzers_manager.classes import DockerBasedAnalyzer, ObservableAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from tests.mock_utils import MockUpResponse

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


class PhunterAnalyzer(ObservableAnalyzer, DockerBasedAnalyzer):
    name: str = "Phunter"
    url: str = "http://phunter:5000/analyze"
    max_tries: int = 1
    poll_distance: int = 0

    def run(self):
        try:
            parsed_number = phonenumbers.parse(self.observable_name)
            if not phonenumbers.is_valid_number(parsed_number):
                logger.error(f"Invalid phone number: {self.observable_name}")
                return {"success": False, "error": "Invalid phone number"}
        except phonenumbers.phonenumberutil.NumberParseException:
            logger.error(f"Phone number parsing failed for: {self.observable_name}")
            raise AnalyzerRunException("Invalid phone number format")

        req_data = {"phone_number": self.observable_name}
        logger.info(f"Sending {self.name} scan request: {req_data} to {self.url}")

        try:
            response = self._docker_run(req_data, analyzer_name=self.name)
            logger.info(f"[{self.name}] Scan successful by Phunter. Result: {response}")
            return response

        except requests.exceptions.RequestException as e:
            logger.error(
                f"[{self.name}] Request failed due to network issue: {e}", exc_info=True
            )
            raise AnalyzerRunException(f"Request error to Phunter API: {e}")

        except ValueError as e:
            logger.error(f"[{self.name}] Invalid response format: {e}", exc_info=True)
            raise AnalyzerRunException(f"Invalid response format from Phunter API: {e}")

    @classmethod
    def update(self):
        pass

    @staticmethod
    def mocked_docker_analyzer_post(*args, **kwargs):
        mock_response = {
            "success": True,
            "report": {
                "valid": "yes",
                "views": "9",
                "carrier": "Vodafone",
                "location": "India",
                "operator": "Vodafone",
                "possible": "yes",
                "line_type": "FIXED LINE OR MOBILE",
                "local_time": "21:34:45",
                "spam_status": "Not spammer",
                "phone_number": "+918929554991",
                "national_format": "089295 54991",
                "international_format": "+91 89295 54991",
            },
        }
        return MockUpResponse(mock_response, 200)
