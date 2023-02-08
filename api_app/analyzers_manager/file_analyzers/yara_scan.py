# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import io
import logging
import zipfile
from pathlib import PosixPath
from typing import List, Optional, Tuple

import requests
import yara
from cache_memoize import cache_memoize
from django.conf import settings
from git import Repo

from api_app.analyzers_manager.classes import FileAnalyzer
from api_app.analyzers_manager.dataclasses import AnalyzerConfig
from api_app.exceptions import AnalyzerRunException

logger = logging.getLogger(__name__)


class YaraScan(FileAnalyzer):
    def set_params(self, params):
        self.result = []
        self.ignore_rules = params.get("ignore", [])

    def load_directory(self, rulepath: PosixPath) -> List[Tuple[PosixPath, yara.Rules]]:
        logger.info(f"Loading directory {rulepath}")
        rules = []
        if rulepath.name == ".git":
            return rules
        for full_path in rulepath.iterdir():
            if full_path.name in self.ignore_rules:
                logger.info(f"Skipping {full_path} because ignored")
                continue

            if full_path.is_file():
                rule = self.compile_rule(full_path)
                if rule:
                    rules.append((full_path, rule))
            else:
                rules += self.load_directory(full_path)
        return rules

    def _validated_matches(self, rules: yara.Rules) -> List:
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

    def compile_rule(self, file_path: PosixPath) -> Optional[yara.Rules]:
        if file_path.exists():
            try:
                if file_path.suffix in [".yar", ".yara", ".rule"]:
                    return yara.compile(
                        str(file_path), externals={"filename": self.filename}
                    )
                elif file_path.suffix == ".yas":
                    return yara.load(str(file_path))
                else:
                    logger.info(f"Unable to compile {file_path}")
            except yara.SyntaxError as e:
                logger.warning(f"Rule {file_path} has a syntax error {e}")

        return None

    def compile_rules(self, directory: PosixPath) -> List[Tuple[PosixPath, yara.Rules]]:
        # you should add an "index.yar" or "index.yas" file
        # and select only the rules you would like to run
        rules = []
        if directory.is_dir():
            index = directory / "index.yas"
            compiled_rule = self.compile_rule(index)
            if compiled_rule:
                rules.append((index, compiled_rule))
            else:
                index = directory / "index.yar"
                compiled_rule = self.compile_rule(index)
                if compiled_rule:
                    rules.append((index, compiled_rule))
                else:
                    rules += self.load_directory(directory)
        else:
            logger.warning(f"Skipping {directory} because it is not really a directory")
        return rules

    @cache_memoize(
        timeout=60 * 60 * 24,
        args_rewrite=lambda s, directory_path: f"{s.__class__.__name__}"
        f"-{str(directory_path)}",
    )
    def get_rules(
        self, directory_path: PosixPath
    ) -> List[Tuple[PosixPath, io.BytesIO]]:
        ruleset = self.compile_rules(directory_path)
        rules_compiled = []
        for path, rules in ruleset:
            logger.info(f"Saving file {path}")
            buff = io.BytesIO()
            rules.save(file=buff)
            buff.seek(0)
            rules_compiled.append((path, buff))
        return rules_compiled

    def run(self):
        directories = list(settings.YARA_RULES_PATH.iterdir())
        if not directories:
            raise AnalyzerRunException("There are no yara rules")
        for directory in directories:
            logger.info(f"Getting rules inside {directory}")
            list_rules_compiled = self.get_rules(directory)
            if not list_rules_compiled:
                raise AnalyzerRunException(
                    f"There are no yara rules installed inside {directory}"
                )
            logger.info(f"There are {len(list_rules_compiled)} rules")

            for path, rules_compiled in list_rules_compiled:
                rule = yara.load(file=rules_compiled)

                matches = self._validated_matches(rule)
                for match in matches:
                    # limited to 20 strings reasons because it could be a very long list
                    self.result.append(
                        {
                            "match": str(match),
                            "strings": str(match.strings[:20]) if match else "",
                            "tags": match.tags,
                            "meta": match.meta,
                            "path": str(path),
                        }
                    )
        return self.result

    @staticmethod
    def download_repository(directory: PosixPath, url: str) -> bool:
        if not directory.exists():
            logger.info(f"About to clone {url} at {directory}")
            Repo.clone_from(url, directory, depth=1)
            return True
        return False

    @classmethod
    def update_repository(cls, directory: PosixPath, url: str):
        if url.endswith(".zip"):
            logger.info(f"About do download zip file from {url}")
            response = requests.get(url, stream=True)
            try:
                response.raise_for_status()
            except Exception as e:
                logger.exception(e)
            else:
                zipfile_ = zipfile.ZipFile(io.BytesIO(response.content))
                zipfile_.extractall(directory)

        else:
            new = cls.download_repository(directory, url)
            if not new:
                logger.info(f"about to pull {url} at {directory}")
                repo = Repo(directory)
                git = repo.git
                git.config("--global", "--add", "safe.directory", directory)
                o = repo.remotes.origin
                o.pull(allow_unrelated_histories=True, rebase=True)

    @classmethod
    def update_rules(cls):
        logger.info("Starting updating yara rules")
        analyzer_config = AnalyzerConfig.all()
        urls = set()
        for analyzer_name, ac in analyzer_config.items():
            if (
                ac.python_module == f"{cls.__module__.split('.')[-1]}.{cls.__name__}"
                and ac.disabled is False
            ):
                new_urls = ac.param_values.get("url", [])
                logger.info(f"Adding urls {new_urls}")
                urls.update(new_urls)
        for url in urls:
            logger.info(f"Going to update {url} yara repo")
            url_list = url.split("/")
            # directory name is organization_repository
            org = url_list[-2]
            # we are removing the .zip, .git. .whatever
            repo = url_list[-1].split(".")[0]
            directory_name = "_".join([org, repo])

            cls.update_repository(settings.YARA_RULES_PATH / directory_name, url)
        logger.info("Finished updating yara rules")
