import json
import logging

from knock.knockpy import KNOCKPY

from api_app.analyzers_manager import classes

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
