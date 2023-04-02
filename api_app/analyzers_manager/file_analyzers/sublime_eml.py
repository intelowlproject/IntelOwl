# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import sublime

from api_app.analyzers_manager.classes import FileAnalyzer
from api_app.exceptions import AnalyzerRunException


class SublimeEML(FileAnalyzer):
    def run(self):
        client = sublime.Sublime()
        # client._BASE_URL = "http://localhost:8000"
        raw_message_eml = sublime.util.load_eml(self.filepath)
        rules, queries = sublime.util.load_yml_path(
            "/opt/deploy/sublime_eml_download/detection-rules"
        )

        try:
            response = client.analyze_raw_message(raw_message_eml, rules, queries)
        except Exception as e:
            raise AnalyzerRunException(e)

        return response
