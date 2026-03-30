import logging
from urllib.parse import quote, urljoin

from api_app import http_utils
from api_app.analyzers_manager import classes

logger = logging.getLogger(__name__)


class MmdbServer(classes.ObservableAnalyzer):
    """
    This analyzer is a wrapper for the mmdb-server project.
    """

    def update(self) -> bool:
        pass

    url: str
    observable_name: str

    def run(self):
        encoded_name = quote(self.observable_name, safe="")
        url = urljoin(self.url, encoded_name)
        response = http_utils.get(url)
        response.raise_for_status()
        return response.json()
