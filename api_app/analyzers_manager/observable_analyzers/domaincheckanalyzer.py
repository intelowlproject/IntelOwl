import logging

from domaincheck import domaincheck

from api_app.analyzers_manager import classes

logger = logging.getLogger(__name__)


class domainCheck(classes.ObservableAnalyzer):
    resolver: str = "8.8.8.8"

    def run(self):
        logger.info(f"Running DomainCheck for {self.observable_name}")
        if not self.resolver:
            self.resolver = None
        result = domaincheck.main(
            [self.observable_name],
            resolver=self.resolver,
        )
        logger.info(f"DomainCheck result: {result}")
        return result

    def update(self):
        pass
