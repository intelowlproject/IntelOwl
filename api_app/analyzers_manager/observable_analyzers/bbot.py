import json
import logging

from bbot.scanner import Scanner

from api_app.analyzers_manager import classes

# from tests.mock_utils import if_mock_connections, patch

logger = logging.getLogger(__name__)


class Bbot(classes.ObservableAnalyzer):

    presets: str

    def run(self):
        logger.info(
            f"running Bbot  Analyzer on {self.observable_name} using {self.presets}"
        )
        return self.bbot_scan(self.observable_name, self.presets)

    def bbot_scan(self, target, presets):
        # if __name__=="__main__":
        scan = Scanner(target, presets=[presets])
        results = []
        for event in scan.start():
            results.append(event.json())
        json_results = json.dumps(results)
        return json.dumps(json_results)
