# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
from machofile import MachO

from api_app.analyzers_manager.classes import FileAnalyzer

logger = logging.getLogger(__name__)


class MachoFileInfo(FileAnalyzer):
    def run(self):
        results = {}

        try:
            macho = MachO(self.filepath)
            results["is_macho"] = True
            results["headers"] = macho.headers
            results["libraries"] = macho.libs

        except Exception as e:
            warning_message = (
                f"job_id:{self.job_id} analyzer:{self.analyzer_name} "
                f"md5:{self.md5} filename:{self.filename} error:{e}"
            )
            logger.warning(warning_message)
            self.report.errors.append(warning_message)
            self.report.status = self.report.STATUSES.FAILED
            self.report.save()

        return results
