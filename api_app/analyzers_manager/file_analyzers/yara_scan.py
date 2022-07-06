# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import io
import logging
import os
import zipfile
from typing import List, Tuple

import requests
import yara
from git import Repo

from api_app.analyzers_manager.classes import FileAnalyzer
from api_app.analyzers_manager.dataclasses import AnalyzerConfig
from api_app.exceptions import AnalyzerRunException

logger = logging.getLogger(__name__)


class YaraScan(FileAnalyzer):
    def set_params(self, params):
        self.directories_with_rules = params.get("directories_with_rules", [])
        self.recursive = params.get("recursive", False)
        self.result = []
        self.ruleset: List[Tuple[str, yara.Rules]] = []

    def load_directory(self, rulepath):
        # if you do not have an index file,...
        # .. just extract all the rules in the .yar files
        for f in os.listdir(rulepath):
            full_path = f"{rulepath}/{f}"
            if os.path.isfile(full_path):
                try:
                    if (
                        full_path.endswith(".yar")
                        or full_path.endswith(".yara")
                        or full_path.endswith(".rule")
                    ):
                        self.ruleset.append(
                            (
                                full_path,
                                yara.compile(
                                    full_path,
                                    externals={"filename": self.filename},
                                ),
                            )
                        )
                    elif full_path.endswith(".yas"):
                        self.ruleset.append((full_path, yara.load(full_path)))
                except yara.SyntaxError as e:
                    logger.warning(f"Rule {full_path} " f"has a syntax error {e}")
                    continue
            else:
                if self.recursive:
                    logger.info(f"Loading directory {full_path}")
                    self.load_directory(full_path)

    def _validated_matches(self, rules: yara.Rules) -> list:
        try:
            return rules.match(self.filepath)
        except yara.Error as e:
            if "internal error" in str(e):
                _, code = str(e).split(":")
                if int(code.strip()) == 30:
                    message = f"Too many matches for {self.filename}"
                    self.result.append({"match": message})
                    logger.warning(message)
                    return []
            raise e

    def run(self):
        for rulepath in self.directories_with_rules:
            # you should add an "index.yar" or "index.yas" file
            # and select only the rules you would like to run
            if os.path.isdir(rulepath):
                if os.path.isfile(rulepath + "/index.yas"):
                    self.ruleset.append((rulepath, yara.load(rulepath + "/index.yas")))
                elif os.path.isfile(rulepath + "/index.yar"):
                    self.ruleset.append(
                        (
                            rulepath,
                            yara.compile(
                                rulepath + "/index.yar",
                                externals={"filename": self.filename},
                            ),
                        )
                    )
                else:
                    self.load_directory(rulepath)

        if not self.ruleset:
            raise AnalyzerRunException("there are no yara rules installed")

        for path, rule in self.ruleset:
            matches = self._validated_matches(rule)
            for match in matches:
                # limited to 20 strings reasons because it could be a very long list
                self.result.append(
                    {
                        "match": str(match),
                        "strings": str(match.strings[:20]) if match else "",
                        "tags": match.tags,
                        "meta": match.meta,
                        "path": path,
                    }
                )

        return self.result

    @staticmethod
    def yara_update_repos():
        logger.info("started pulling images from yara public repos")
        analyzer_config = AnalyzerConfig.all()
        found_yara_dirs = []
        for analyzer_name, ac in analyzer_config.items():
            if analyzer_name.startswith("Yara_Scan") and ac.param_values.get(
                "update", True
            ):
                yara_dirs = ac.param_values.get("git_repo_main_dir", [])
                if not yara_dirs:
                    yara_dirs = ac.param_values.get("directories_with_rules", [])
                yara_urls = ac.param_values.get("url", [])
                if yara_urls:
                    for yara_url, yara_dir in zip(yara_urls, yara_dirs):
                        response = requests.get(yara_url, stream=True)
                        zipfile_ = zipfile.ZipFile(io.BytesIO(response.content))
                        zipfile_.extractall(yara_dir)
                        logger.info(f"download {yara_url}")
                else:
                    for yara_dir in yara_dirs:
                        if os.path.isdir(yara_dir):
                            repo = Repo(yara_dir)
                            o = repo.remotes.origin
                            o.pull()
                            logger.info(f"pull repo on {yara_dir} dir")
                        else:
                            logger.warning(f"yara dir {yara_dir} does not exist")
                found_yara_dirs.extend(yara_dirs)
        return found_yara_dirs
