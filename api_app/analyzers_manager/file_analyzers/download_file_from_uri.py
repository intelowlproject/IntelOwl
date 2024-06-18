# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging

import requests

from api_app.analyzers_manager.classes import ObservableAnalyzer

logger = logging.getLogger(__name__)


class DownloadFileFromUri(ObservableAnalyzer):
    http_proxy: str

    def run(self):
        proxies = {
            "http": self.http_proxy,
        }
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/126.0.0.0 Safari/537.36 Edg/125.0.2535.92",
            "Content-type": "application/octet-stream",
        }

        r = requests.get(
            self.uri, headers=headers, proxies=proxies, allow_redirects=True, timeout=60
        )
        sample = open("file", "wb")
        sample.write(r.content)
        sample.flush()
        sample.close()

        return "file"
