import logging

from api_app.analyzers_manager.classes import DockerBasedAnalyzer, FileAnalyzer

logger = logging.getLogger(__name__)


class PhishingFormCompiler(FileAnalyzer, DockerBasedAnalyzer):
    def run(self) -> dict:
        if not (target_site := self._job.parent_job.parent_job.observable_name):
            logger.info("Target site not found! Proceeding with only source code.")
        print(target_site)
