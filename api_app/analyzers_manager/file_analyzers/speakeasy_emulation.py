# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
import speakeasy

from api_app.analyzers_manager.classes import FileAnalyzer

logger = logging.getLogger(__name__)


class SpeakEasy(FileAnalyzer):
    def run(self):
        results = {}
        s = speakeasy.Speakeasy()
        m = s.load_module(self.filepath)
        s.run_module(m)
        results = s.get_report()

        return results
