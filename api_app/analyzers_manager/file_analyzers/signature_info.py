# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
from subprocess import DEVNULL, PIPE, Popen

from celery.exceptions import SoftTimeLimitExceeded
from django.conf import settings

from api_app.analyzers_manager.classes import FileAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException

logger = logging.getLogger(__name__)


class SignatureInfo(FileAnalyzer):
    def run(self):
        p = None
        results = {
            "checksum_mismatch": False,
            "no_signature": False,
            "verified": False,
            "corrupted": False,
            "certificate_has_expired": False,
        }
        try:
            command = [
                f"{settings.PROJECT_LOCATION}/docker/bin/osslsigncode",
                "verify",
                self.filepath,
            ]
            p = Popen(command, stdin=DEVNULL, stdout=PIPE, stderr=PIPE)
            (out, err) = p.communicate()
            output = out.decode()

            if p.returncode == 1:
                if "MISMATCH" in output:
                    results["checksum_mismatch"] = True
                # new versions (>=2.0) provide this status code
                # when the signature is not found
                elif "No signature found" in output:
                    results["no_signature"] = True
            elif p.returncode != 0:
                raise AnalyzerRunException(f"osslsigncode return code is {p.returncode}. Error: {err}")

            if output:
                if "No signature found" in output:
                    results["no_signature"] = True
                if "Signature verification: ok" in output:
                    results["verified"] = True
                if "Corrupt PE file" in output:
                    results["corrupted"] = True
                if "certificate has expired" in output:
                    results["certificate_has_expired"] = True
            else:
                raise AnalyzerRunException("osslsigncode gave no output?")

        # we should stop the subprocesses...
        # .. in case we reach the time limit for the celery task
        except SoftTimeLimitExceeded as exc:
            self._handle_exception(exc)
            if p:
                p.kill()

        return results
