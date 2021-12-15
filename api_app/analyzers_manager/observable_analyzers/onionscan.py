"""
This IntelOwl module adds onionscan utility support to scan tor .onion domains.
"""
# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import json
import subprocess
from shutil import which

# multi platform support
from sys import platform

from api_app.analyzers_manager import classes
from api_app.exceptions import AnalyzerRunException


class OnionScan(classes.ObservableAnalyzer):
    """
        Scans domains with onionscan for misconfigurations and leaks
    """
    onionscan_binary: str = "/opt/deploy/onionscan/onionscan"
    # default target protonmail website
    target = "https://protonmailrmez3lotccipshtkleegetolb73fuirgj7r4o4vfu7ozyd.onion/"


    def set_params(self, params):
        """
            params:
                - "target" : "target url for onionscan" (default protonmail)
        """
        self.target = params.get("target", self.target)


    def run(self):
        """
            Run Onionscan against target onion url
        """
        # Check for onionscan binary in path/pwd.
        if which("onionscan"):
            self.onionscan_binary = "onionscan"
        if not which(self.onionscan_binary):
            raise AnalyzerRunException("onionscan is not installed!")
        # Open a pipe to onionscan process
        command = "%s --%s %s" % (self.onionscan_binary, "jsonReport", self.target)
        process = subprocess.Popen(
            [command, self.observable_name],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        process.wait()
        # read std with utf-8 encoding
        stdout, stderr = process.communicate()
        onionscan_stdout = stdout.decode("utf-8"), stderr
        onionscan_report = onionscan_stdout[0]
        # load stdout json and return to user
        onionscan_json_report = json.loads(onionscan_report)
        return onionscan_json_report
