import logging
import os
import pathlib

import requests
import yara_x
from django.conf import settings

from api_app.analyzers_manager.classes import FileAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.mixins import RulesUtiliyMixin

logger = logging.getLogger(__name__)


RULES_URL = "https://api.github.com/repos/YARAHQ/yara-forge/releases/latest"
BASE_RULES_LOCATION = f"{settings.MEDIA_ROOT}/yarax"


class YaraX(FileAnalyzer, RulesUtiliyMixin):
    rule_set: str = "core"

    def get_rule_location(self):
        logger.info(f"Searching for rules at {BASE_RULES_LOCATION}/{self.rule_set}")
        try:
            rule_set_dir = pathlib.Path(BASE_RULES_LOCATION) / self.rule_set
            rule = rule_set_dir.rglob("*.yar")
            return next(rule).__str__()

        except StopIteration as e:
            logger.error(f"{self.rule_set} not found, function exited with error {e}")
            raise AnalyzerRunException(f"{self.rule_set} rules not present")

    @classmethod
    def update(cls, rule_set, analyzer_module) -> bool:
        logger.info(f"Updating {rule_set} rule set")
        rule_set_download_url = ""
        filename = ""
        try:
            response = requests.get(RULES_URL)
            assets = response.json()["assets"]
            latest_version = response.json()["tag_name"]
            for asset in assets:
                if rule_set in asset["browser_download_url"]:
                    rule_set_download_url = asset["browser_download_url"]
                    filename = asset["name"]
                    break

            rule_set_directory = f"{BASE_RULES_LOCATION}/{rule_set}"
            rule_file_path = f"{rule_set_directory}/{filename}"

            cls._download_rules(
                rule_set_download_url,
                rule_set_directory,
                rule_file_path,
                latest_version,
                analyzer_module,
            )

            rule_file_path = pathlib.Path(BASE_RULES_LOCATION) / rule_set / filename

            cls._unzip(rule_file_path)

            logger.info(f"Successfully updated {rule_set} rules")
            return True

        except Exception as e:
            logger.exception(f"Failed to update yara-forge rules. Error: {e}")
            raise AnalyzerRunException(
                f"Failed to update yara-forge ruleset. Error: {e}"
            )

        return False

    def run(self):

        if self.rule_set not in ("core", "extended", "full"):
            raise AnalyzerRunException(
                "Please select the correct ruleset pack from available options."
                " Available options are core, extended, full"
            )

        rule_dir = f"{BASE_RULES_LOCATION}/{self.rule_set}"

        response = requests.get(RULES_URL)

        latest_version = response.json()["tag_name"]

        update_status = (
            True
            if self._check_if_latest_version(latest_version, self.python_module)
            else self.update(self.rule_set, self.python_module)
        )

        if not os.path.isdir(rule_dir) and not update_status:
            raise AnalyzerRunException(f"Couldn't update {self.rule_set} rules")

        rules_file_path = self.get_rule_location()
        logger.info(f"Found rules at {rules_file_path}")

        with open(rules_file_path, mode="r") as f:
            rules_source = f.read()

        try:
            logger.info(f"Compiling rules present at {self.rule_set}")
            compiler = yara_x.Compiler()
            compiler.add_source(rules_source, origin=rules_file_path)
            rules = compiler.build()
            logger.info("Successfully compiled and built rules")

            logger.info(
                f"Starting scanning file: {self.filename} having hash: {self.md5} with {self.rule_set} rules"
            )
            scanner = yara_x.Scanner(rules)

            result = []
            scan_results = scanner.scan_file(self.filepath)
            for rule in scan_results.matching_rules:
                logger.info(f"Rule Identifier: {rule.identifier}")
                rule_metadata = dict(rule.metadata)
                rule_details = {
                    "rule_identifier": rule.identifier,
                    "rule_metadata": rule_metadata,
                    "pattern_details": [],
                }
                for pattern in rule.patterns:
                    pattern_details = {
                        "pattern_identifier": pattern.identifier,
                        "match_details": [],
                    }

                    for match in pattern.matches:
                        match_details = {
                            "match_offset": match.offset,
                            "match_length": match.length,
                            "match_xor_key": match.xor_key,
                        }
                        pattern_details["match_details"].append(match_details)

                    rule_details["pattern_details"].append(pattern_details)

                result.append(rule_details)

            logger.info(f"Successfully scanned {self.filename} with hash {self.md5}")

            return {"results": "No Match"} if not result else {"results": result}

        except yara_x.CompileError as e:
            logger.error(
                f"Failed to compile {self.rule_set} rules present at {rules_file_path} with error {e}"
            )
            raise AnalyzerRunException(f"Failed to compile {self.rule_set} rules")

        except yara_x.ScanError as e:
            logger.error(f"Failed to scan file {self.filename} with error {e}")
            raise AnalyzerRunException(f"Failed to scan {self.filename}")

        except yara_x.TimeoutError as e:
            logger.error(f"Failed with timeout with error {e}")
            raise AnalyzerRunException("Failed with timeout")
