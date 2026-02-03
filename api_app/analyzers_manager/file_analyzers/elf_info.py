# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import logging

from elftools.common.exceptions import ELFError
from elftools.construct import Container
from elftools.elf.elffile import ELFFile
from telfhash import telfhash

from api_app.analyzers_manager.classes import FileAnalyzer

logger = logging.getLogger(__name__)


class ELFInfo(FileAnalyzer):
    @staticmethod
    def _convert_to_dict(element):
        if type(element) is Container:
            return {key: ELFInfo._convert_to_dict(value) for key, value in element.items()}
        else:
            return element

    def run(self):
        results = {}
        try:
            with open(self.filepath, "rb") as file:
                elf = ELFFile(file)
            if elf is None:
                raise ELFError("Not an ELF file")
            try:
                results["telf"] = telfhash(self.filepath)[0]
            except IndexError:
                raise ELFError("Not an ELF file")

            results["telf"].pop("file", None)
            results["header"] = self._convert_to_dict(elf.header)
            results["elfclass"] = elf.elfclass
            results["little_endian"] = elf.little_endian

        except ELFError as e:
            warning_message = (
                f"job_id:{self.job_id} analyzer:{self.analyzer_name}"
                f" md5:{self.md5} filename: {self.filename} ELFError {e}"
            )
            logger.warning(warning_message)
            self.report.errors.append(warning_message)
            self.report.status = self.report.STATUSES.FAILED
            self.report.save()

        return results
