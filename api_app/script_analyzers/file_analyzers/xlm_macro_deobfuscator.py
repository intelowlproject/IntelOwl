import logging
from XLMMacroDeobfuscator.deobfuscator import process_file
from api_app.script_analyzers.classes import FileAnalyzer
from celery.exceptions import SoftTimeLimitExceeded

logger = logging.getLogger(__name__)


class XlmMacroDeobfuscator(FileAnalyzer):
    def set_config(self, additional_config_params):
        self.passwords_to_check = [""]
        additional_passwords_to_check = additional_config_params.get(
            "passwords_to_check", []
        )
        if isinstance(additional_passwords_to_check, list):
            self.passwords_to_check.extend(additional_passwords_to_check)
        elif isinstance(additional_passwords_to_check, str):
            self.passwords_to_check.append(additional_passwords_to_check)

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
            self._handle_base_exception("Soft Time Limit Exceeded")
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
                results["correct_password"] = xlmpassword
                results["decrypted"] = True
            else:
                results["was_unencrypted"] = True
            return results
        except Exception as e:
            if "Failed to decrypt" in str(e):
                return {}
            return {"errors": str(e)}
