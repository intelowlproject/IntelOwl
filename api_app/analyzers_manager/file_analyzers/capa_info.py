# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import json
import logging
import os
import shutil
import subprocess
from pathlib import Path
from shlex import quote

import requests
from django.conf import settings

from api_app.analyzers_manager.classes import FileAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.analyzers_manager.models import PythonModule
from api_app.mixins import RulesUtiliyMixin

logger = logging.getLogger(__name__)

BASE_LOCATION = f"{settings.MEDIA_ROOT}/capa"
RULES_LOCATION = f"{BASE_LOCATION}/capa-rules"
SIGNATURE_LOCATION = f"{BASE_LOCATION}/sigs"
RULES_FILE = f"{RULES_LOCATION}/capa_rules.zip"
RULES_URL = "https://github.com/mandiant/capa-rules/archive/refs/tags/"


class CapaInfo(FileAnalyzer, RulesUtiliyMixin):
    shellcode: bool
    arch: str
    timeout: float = 15
    force_pull_signatures: bool = False

    @classmethod
    def _download_signatures(cls) -> None:
        logger.info(f"Downloading signatures at {SIGNATURE_LOCATION} now")

        if os.path.exists(SIGNATURE_LOCATION):
            logger.info(f"Removing existing signatures at {SIGNATURE_LOCATION}")
            shutil.rmtree(SIGNATURE_LOCATION)

        os.makedirs(SIGNATURE_LOCATION)
        logger.info(f"Created fresh signatures directory at {SIGNATURE_LOCATION}")

        signatures_url = "https://api.github.com/repos/mandiant/capa/contents/sigs"
        try:
            response = requests.get(signatures_url)
            signatures_list = response.json()

            for signature in signatures_list:

                filename = signature["name"]
                download_url = signature["download_url"]

                signature_file_path = os.path.join(SIGNATURE_LOCATION, filename)

                sig_content = requests.get(download_url, stream=True)
                with open(signature_file_path, mode="wb") as file:
                    for chunk in sig_content.iter_content(chunk_size=10 * 1024):
                        file.write(chunk)

        except Exception as e:
            logger.error(f"Failed to download signature: {e}")
            raise AnalyzerRunException("Failed to update signatures")
        logger.info("Successfully updated signatures")

    @classmethod
    def update(cls, anayzer_module: PythonModule) -> bool:
        try:
            logger.info("Updating capa rules")
            response = requests.get(
                "https://api.github.com/repos/mandiant/capa-rules/releases/latest"
            )
            latest_version = response.json()["tag_name"]
            capa_rules_download_url = RULES_URL + latest_version + ".zip"

            cls._download_rules(
                rule_set_download_url=capa_rules_download_url,
                rule_set_directory=RULES_LOCATION,
                rule_file_path=RULES_FILE,
                latest_version=latest_version,
                analyzer_module=anayzer_module,
            )

            cls._unzip(Path(RULES_FILE))

            logger.info("Successfully updated capa rules")

            return True

        except Exception as e:
            logger.error(f"Failed to update capa rules with error: {e}")

        return False

    def run(self):
        try:

            response = requests.get(
                "https://api.github.com/repos/mandiant/capa-rules/releases/latest"
            )
            latest_version = response.json()["tag_name"]

            capa_analyzer_module = self.python_module

            update_status = (
                True
                if self._check_if_latest_version(latest_version, capa_analyzer_module)
                else self.update(capa_analyzer_module)
            )

            if self.force_pull_signatures or not os.path.isdir(SIGNATURE_LOCATION):
                self._download_signatures()

            if not (os.path.isdir(RULES_LOCATION)) and not update_status:

                raise AnalyzerRunException("Couldn't update capa rules")

            command: list[str] = ["/usr/local/bin/capa", "--quiet", "--json"]
            shell_code_arch = "sc64" if self.arch == "64" else "sc32"
            if self.shellcode:
                command.append("-f")
                command.append(shell_code_arch)

            # Setting default capa-rules path
            command.append("-r")
            command.append(RULES_LOCATION)

            # Setting default signatures location
            command.append("-s")
            command.append(SIGNATURE_LOCATION)

            command.append(quote(self.filepath))

            logger.info(
                f"Starting CAPA analysis for {self.filename} with hash: {self.md5} and command: {command}"
            )

            process: subprocess.CompletedProcess = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=True,
            )

            result = json.loads(process.stdout)
            result["command_executed"] = command
            result["rules_version"] = latest_version

            logger.info(
                f"CAPA analysis successfully completed for file: {self.filename} with hash {self.md5}"
            )

        except subprocess.CalledProcessError as e:
            stderr = e.stderr
            logger.info(
                f"Capa Info failed to run for {self.filename} with hash: {self.md5} with command {e}"
            )
            raise AnalyzerRunException(
                f" Analyzer for {self.filename} with hash: {self.md5} failed with error: {stderr}"
            )

        return result
