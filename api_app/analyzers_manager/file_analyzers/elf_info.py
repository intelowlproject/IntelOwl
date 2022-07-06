# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging

from elftools.common.exceptions import ELFError
from elftools.elf.elffile import ELFFile
from telfhash import telfhash

from api_app.analyzers_manager.classes import FileAnalyzer

logger = logging.getLogger(__name__)


class ELFInfo(FileAnalyzer):
    def run(self):
        results = {}
        try:
            with open(self.filepath, "rb") as file:
                elf = ELFFile(file)
            if elf is None:
                raise ELFError("Not an ELF file")
            results["telf"] = telfhash(self.filepath)[0]
            results["telf"].pop("file", None)

        except ELFError as e:
            warning_message = (
                f"job_id:{self.job_id} analyzer:{self.analyzer_name}"
                f" md5:{self.md5} filename: {self.filename} ELFError {e}"
            )
            logger.warning(warning_message)
            self.report.errors.append(warning_message)
            self.report.status = self.report.Status.FAILED
            self.report.save()

        return results
