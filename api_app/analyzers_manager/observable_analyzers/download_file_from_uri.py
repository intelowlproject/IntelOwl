# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
import os
import re
import unicodedata
from urllib.parse import unquote, urlparse

import requests

from api_app.analyzers_manager.classes import ObservableAnalyzer

logger = logging.getLogger(__name__)


# https://github.com/django/django/blob/master/django/utils/text.py
def custom_slugify(value, allow_unicode=False):
    value = str(value)
    if allow_unicode:
        value = unicodedata.normalize("NFKC", value)
    else:
        value = (
            unicodedata.normalize("NFKD", value)
            .encode("ascii", "ignore")
            .decode("ascii")
        )
    # clear strange chars
    return re.sub(r"[\\\"'$&%/#@()]", "", value)


class DownloadFileFromUri(ObservableAnalyzer):
    basefolder: str
    _http_proxy: str

    def run(self):
        result = {"errors": [], "stored_in": ""}

        if not os.path.exists(self.basefolder):
            os.makedirs(self.basefolder)

        proxies = {"http": self._http_proxy} if self._http_proxy else {}
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/126.0.0.0 Safari/537.36 Edg/125.0.2535.92",
            "Content-type": "application/octet-stream",
        }

        try:
            r = requests.get(
                self.observable_name,
                headers=headers,
                proxies=proxies,
                allow_redirects=True,
                timeout=50,
            )
        except requests.exceptions.Timeout as e:
            result["errors"].append(f"timeout: {e}")
        except requests.exceptions.TooManyRedirects as e:
            result["errors"].append(f"too many requests: {e}")
        except requests.exceptions.HTTPError as e:
            result["errors"].append(f"http error: {e}")
        except requests.exceptions.ConnectionError as e:
            result["errors"].append(f"connection error: {e}")
        except requests.exceptions.RequestException as e:
            result["errors"].append(f"catastrophic error: {e}")
        else:
            if filename := custom_slugify(
                os.path.basename(urlparse(unquote(self.observable_name)).path)
            ):
                with open(os.path.join(self.basefolder, filename), "wb") as tmp:
                    tmp.write(r.content)
                    tmp.flush()
                    tmp.close()
                    result["stored_in"] = os.path.join(self.basefolder, filename)
        return result
