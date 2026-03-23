# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import base64
import logging

import requests

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException

logger = logging.getLogger(__name__)


class DownloadFileFromUri(ObservableAnalyzer):
    _http_proxy: str
    header_user_agent: str
    header_cookies: str
    header_content_type: str
    header_accept: str
    timeout: int

    @classmethod
    def update(cls) -> bool:
        pass

    def run(self):
        result = {"stored_base64": []}

        proxies = {"http": self._http_proxy} if self._http_proxy else {}
        headers = {
            "User-Agent": self.header_user_agent,
            "Cookie": self.header_cookies,
            "Content-type": self.header_content_type,
            "Accept": self.header_accept,
        }

        try:
            r = requests.get(
                self.observable_name,
                headers=headers,
                proxies=proxies,
                timeout=self.timeout,
            )
        except Exception as e:
            raise AnalyzerRunException(f"requests exception: {e}")
        else:
            if r.content:
                if "text/html" not in r.headers["Content-Type"]:
                    result["stored_base64"].append(base64.b64encode(r.content).decode("ascii"))
                else:
                    logger.info(f"discarded text/html response for {self.observable_name}")
            else:
                logger.info(f"no response content for {self.observable_name}")

        return result
