import os
import logging
import yara

from git import Repo

from api_app.exceptions import AnalyzerRunException
from api_app.script_analyzers.classes import FileAnalyzer
from api_app.utilities import get_analyzer_config

logger = logging.getLogger(__name__)


class YaraScan(FileAnalyzer):
    def set_config(self, additional_config_params):
        self.directories_with_rules = additional_config_params.get(
            "directories_with_rules", []
        )

    def run(self):
        ruleset = []
        for rulepath in self.directories_with_rules:
            # you should add a "index.yar" or "index.yas" file
            # and select only the rules you would like to run
            if os.path.isdir(rulepath):
                if os.path.isfile(rulepath + "/index.yas"):
                    ruleset.append(yara.load(rulepath + "/index.yas"))
                elif os.path.isfile(rulepath + "/index.yar"):
                    ruleset.append(
                        yara.compile(
                            rulepath + "/index.yar",
                            externals={"filename": self.filename},
                        )
                    )
                else:
                    # if you do not have an index file,...
                    # .. just extract all the rules in the .yar files
                    for f in os.listdir(rulepath):
                        full_path = f"{rulepath}/{f}"
                        if os.path.isfile(full_path):
                            if full_path.endswith(".yar"):
                                ruleset.append(
                                    yara.compile(
                                        full_path, externals={"filename": self.filename}
                                    )
                                )
                            elif full_path.endswith(".yas"):
                                ruleset.append(yara.load(full_path))

        if not ruleset:
            raise AnalyzerRunException("there are no yara rules installed")

        result = []
        for rule in ruleset:
            matches = rule.match(self.filepath)
            for match in matches:
                # limited to 20 strings reasons because it could be a very long list
                result.append(
                    {
                        "match": str(match),
                        "strings": str(match.strings[:20]) if match else "",
                        "tags": match.tags,
                        "meta": match.meta,
                    }
                )

        return result

    @staticmethod
    def yara_update_repos():
        logger.info("started pulling images from yara public repos")
        analyzer_config = get_analyzer_config()
        found_yara_dirs = []
        for analyzer_name, analyzer_config in analyzer_config.items():
            if analyzer_name.startswith("Yara_Scan"):
                yara_dirs = analyzer_config.get("additional_config_params", {}).get(
                    "git_repo_main_dir", []
                )
                if not yara_dirs:
                    # fall back to required key
                    yara_dirs = analyzer_config.get("additional_config_params", {}).get(
                        "directories_with_rules", []
                    )
                    found_yara_dirs.extend(yara_dirs)
                # customize it as you wish
                for yara_dir in yara_dirs:
                    if os.path.isdir(yara_dir):
                        repo = Repo(yara_dir)
                        o = repo.remotes.origin
                        o.pull()
                        logger.info(f"pull repo on {yara_dir} dir")
                    else:
                        logger.warning(f"yara dir {yara_dir} does not exist")

        return found_yara_dirs
