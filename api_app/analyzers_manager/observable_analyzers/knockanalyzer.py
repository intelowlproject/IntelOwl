import json
import logging

from knock.knockpy import KNOCKPY

from api_app.analyzers_manager import classes
from tests.mock_utils import MockUpResponse, if_mock_connections, patch

logger = logging.getLogger(__name__)


class KnockAnalyzer(classes.ObservableAnalyzer):
    """
    This analyzer is a wrapper for the knockpy project.
    """

    observable_name: str
    dns: str = None
    useragent: str = None
    timeout: int = None
    threads: int = None
    recon: bool = True
    bruteforce: bool = True

    def update(self) -> bool:
        pass

    def run(self):
        logger.info(f"Running KnockAnalyzer for {self.observable_name}")
        results = KNOCKPY(
            domain=self.observable_name,
            dns=self.dns,
            useragent=self.useragent,
            timeout=self.timeout,
            threads=self.threads,
            recon=self.recon,
            bruteforce=self.bruteforce,
        )

        return json.dumps(results)

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "knock.knockpy.KNOCKPY",
                    return_value=MockUpResponse(
                        {
                            "marcia.domain.com": ["66.96.162.92"],
                            "http": [404, None, "Apache"],
                            "https": [None, None, None],
                            "cert": [None, None],
                        },
                        {
                            "mbsizer.domain.com": ["66.96.162.92"],
                            "http": [404, None, "Apache"],
                            "https": [None, None, None],
                            "cert": [None, None],
                        },
                        200,
                    ),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
