import subprocess
import logging
from shutil import which
import pyclamd

from api_app.exceptions import AnalyzerRunException
from api_app.analyzers_manager.classes import FileAnalyzer


logger = logging.getLogger(__name__)


class ClamAV(FileAnalyzer):
    command: str = "clamd"
    update_database_command: str = "freshclam"

    def run(self):
        if not which(self.update_database_command):
            logger.warning("Skipping Database updates: freshclam not installed")

        if not which(self.command):
            raise AnalyzerRunException("clamav not installed!")

        # Update database if needed and run ClamAV Daemon
        args = [self.update_database_command, "&&", self.command]

        process = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stdout, stderr = process.communicate()
        logger.warning(stderr.decode("utf-8"))

        try:
            cd = pyclamd.ClamdUnixSocket()
            # Test if server is reachable
            cd.ping()
        except pyclamd.ConnectionError:
            cd = pyclamd.ClamdNetworkSocket()
            try:
                cd.ping()
            except pyclamd.ConnectionError:
                raise AnalyzerRunException(
                    "couldn't connect to clamd server by unix or network socket"
                )

        try:
            report = cd.scan_stream(self.read_file_bytes())
        except pyclamd.BufferTooLongError as e:
            raise AnalyzerRunException(f"file buffer size exceeds clamd limits: {e}")
        except pyclamd.ConnectionError as e:
            raise AnalyzerRunException(f"communication issue with clamd: {e}")

        return {"data": report}
