import logging

from subprocess import Popen, DEVNULL, PIPE

from celery.exceptions import SoftTimeLimitExceeded

from api_app.exceptions import AnalyzerRunException
from api_app.script_analyzers.classes import FileAnalyzer

logger = logging.getLogger(__name__)


class SignatureInfo(FileAnalyzer):
    def run(self):
        p = None
        results = {
            "checksum_mismatch": False,
            "no_signature": False,
            "verified": False,
            "corrupted": False,
        }
        try:
            command = ["osslsigncode", "verify", self.filepath]
            p = Popen(command, stdin=DEVNULL, stdout=PIPE, stderr=PIPE)
            (out, err) = p.communicate()
            output = out.decode()

            if p.returncode == 1 and "MISMATCH" in output:
                results["checksum_mismatch"] = True
            elif p.returncode != 0:
                raise AnalyzerRunException(
                    f"osslsigncode return code is {p.returncode}. Error: {err}"
                )

            if output:
                if "No signature found" in output:
                    results["no_signature"] = True
                if "Signature verification: ok" in output:
                    results["verified"] = True
                if "Corrupt PE file" in output:
                    results["corrupted"] = True
            else:
                raise AnalyzerRunException("osslsigncode gave no output?")

        except SoftTimeLimitExceeded as e:
            error_message = (
                f"job_id:{self.job_id} analyzer:{self.analyzer_name} md5:{self.md5}"
                f"filename: {self.filename}. Soft Time Limit Exceeded Error {e}"
            )
            logger.error(error_message)
            self.report["errors"].append(str(e))
            self.report["success"] = False
            # we should stop the subprocesses...
            # .. in case we reach the time limit for the celery task
            if p:
                p.kill()

        return results
