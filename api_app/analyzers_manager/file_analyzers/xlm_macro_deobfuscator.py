# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging

from celery.exceptions import SoftTimeLimitExceeded
from XLMMacroDeobfuscator.deobfuscator import process_file

from api_app.analyzers_manager.classes import FileAnalyzer

logger = logging.getLogger(__name__)


class XlmMacroDeobfuscator(FileAnalyzer):
    passwords_to_check: list

    @classmethod
    def update(cls) -> bool:
        pass

    def run(self):
        results = {}
        try:
            for password in self.passwords_to_check:
                results = self.decrypt(password)
                if results:
                    break
            if not results:
                results["error"] = "Can't decrypt with current passwords"
        except SoftTimeLimitExceeded:
            self._handle_exception("Soft Time Limit Exceeded", is_base_err=True)
        return results

    def decrypt(self, xlmpassword=""):
        args = {
            "file": self.filepath,
            "noindent": True,
            "noninteractive": True,
            "return_deobfuscated": True,
            "output_level": 3,
        }
        if xlmpassword:
            args["password"] = xlmpassword
        try:
            results = {"output": process_file(**args)}
            if xlmpassword:
                results["password_tested_for_decryption"] = xlmpassword
            return results
        except Exception as e:
            if "Failed to decrypt" in str(e):
                return {}
            return {"errors": str(e)}
