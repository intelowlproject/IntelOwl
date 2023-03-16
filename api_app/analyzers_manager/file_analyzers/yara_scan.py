# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import dataclasses
import io
import logging
import os
import zipfile
from collections import defaultdict
from pathlib import PosixPath
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from urllib.parse import urlparse

import requests
import yara
from cache_memoize import cache_memoize
from django.conf import settings
from git import Repo

from api_app.analyzers_manager.classes import FileAnalyzer
from api_app.exceptions import AnalyzerRunException
from api_app.models import PluginConfig
from intel_owl.settings._util import set_permissions

logger = logging.getLogger(__name__)


@dataclasses.dataclass
class YaraMatchMock:
    match: str
    strings: List = dataclasses.field(default_factory=list)
    tags: List = dataclasses.field(default_factory=list)
    meta: Dict = dataclasses.field(default_factory=dict)

    def __str__(self):
        return self.match


class YaraScan(FileAnalyzer):

    IGNORE_DIRECTORIES = [".git", ".github"]

    def set_params(self, params):
        self.ignore_rules = params.get("ignore", [])
        self.public_repositories = params.get("public_repositories", [])
        self.private_repositories = list(
            self._secrets.get("private_repositories", {}).keys()
        )
        self.local_rules = params.get("local_rules", False)
        self.missing_paths = 0

    def _load_directory(
        self, rulepath: PosixPath
    ) -> List[Tuple[PosixPath, yara.Rules]]:
        logger.info(f"Loading directory {rulepath}")
        rules = []
        if rulepath.name in self.IGNORE_DIRECTORIES:
            return rules
        for full_path in rulepath.iterdir():
            if full_path.name in self.ignore_rules:
                logger.info(f"Skipping {full_path} because ignored")
                continue

            if full_path.is_file():
                rule = self._compile_rule(full_path)
                if rule:
                    rules.append((full_path, rule))
            else:
                rules += self._load_directory(full_path)
        return rules

    def _validated_matches(self, rules: yara.Rules) -> List:
        try:
            return rules.match(self.filepath, externals={"filename": self.filename})
        except yara.Error as e:
            if "internal error" in str(e):
                _, code = str(e).split(":")
                if int(code.strip()) == 30:
                    message = f"Too many matches for {self.filename}"
                    logger.warning(message)
                    return [YaraMatchMock(message)]
            raise e

    @staticmethod
    def _compile_rule(file_path: PosixPath) -> Optional[yara.Rules]:
        if file_path.exists():
            try:
                if file_path.suffix in [".yar", ".yara", ".rule"]:
                    return yara.compile(
                        str(file_path),
                    )
                elif file_path.suffix == ".yas":
                    return yara.load(str(file_path))
                else:
                    logger.info(f"Unable to compile {file_path}")
            except yara.SyntaxError as e:
                logger.warning(f"Rule {file_path} has a syntax error {e}")

        return None

    def _compile_rules(
        self, directory: PosixPath
    ) -> List[Tuple[PosixPath, yara.Rules]]:
        # you should add an "index.yar" or "index.yas" file
        # and select only the rules you would like to run
        rules = []
        if directory.is_dir():
            index = directory / "index.yas"
            compiled_rule = self._compile_rule(index)
            if compiled_rule:
                rules.append((index, compiled_rule))
            else:
                index = directory / "index.yar"
                compiled_rule = self._compile_rule(index)
                if compiled_rule:
                    rules.append((index, compiled_rule))
                else:
                    rules += self._load_directory(directory)
        else:
            logger.warning(f"Skipping {directory} because it is not really a directory")
        return rules

    # we are caching each directory for 1 year invalidate
    @cache_memoize(
        timeout=60 * 60 * 24,
        args_rewrite=lambda s, directory_path: f"{s.__class__.__name__ if isinstance(s, YaraScan) else s.__name__}"  # noqa
        f"-{str(directory_path)}",
    )
    def _get_rules(
        self, directory_path: PosixPath
    ) -> List[Tuple[PosixPath, io.BytesIO]]:
        ruleset = self._compile_rules(directory_path)
        rules_compiled = []
        for path, rules in ruleset:
            logger.info(f"Saving file {path}")
            buff = io.BytesIO()
            rules.save(file=buff)
            buff.seek(0)
            rules_compiled.append((path, buff))
        return rules_compiled

    def _analyze_directory(self, directory: PosixPath) -> List[Dict[str, Any]]:
        result = []
        if not directory.exists() and not settings.STAGE_CI:
            self.report.errors.append(f"There is no directory {directory} to check")
            self.missing_paths += 1
            return result

        logger.info(f"Getting rules inside {directory}")
        list_rules_compiled = self._get_rules(directory)
        if not list_rules_compiled and not settings.STAGE_CI:
            self.report.errors.append(
                f"There are no yara rules installed inside {directory}"
            )

        logger.info(f"There are {len(list_rules_compiled)} rules")

        for path, rules_compiled in list_rules_compiled:
            rule = yara.load(file=rules_compiled)

            matches = self._validated_matches(rule)
            for match in matches:
                # limited to 20 strings reasons because it could be a very long list
                result.append(
                    {
                        "match": str(match),
                        "strings": str(match.strings[:20]) if match else "",
                        "tags": match.tags,
                        "meta": match.meta,
                        "path": str(path),
                    }
                )
        return result

    def analyze(self, url: str, private: bool = False) -> List[Dict[str, Any]]:
        from certego_saas.apps.organization.membership import Membership

        if private:
            # private rules are downloaded in the user directory
            directory = self._get_directory(url, self._job.user.username)
            # or, if are set at organization level, in the organization owner directory
            if not directory.exists():
                try:
                    membership = self._job.user.membership
                except Membership.DoesNotExist:
                    # user has no org,
                    # he is trying to access a repo that he does not own
                    self.report.errors.append(
                        f"There are no rules downloaded for {url}"
                    )
                    return []
                else:
                    owner = (
                        f"{membership.organization.name}."
                        f"{membership.organization.owner}"
                    )
                    directory = self._get_directory(url, owner)
        else:
            directory = self._get_directory(url)

        return self._analyze_directory(directory)

    def run(self):
        if not self.public_repositories and not self.private_repositories:
            raise AnalyzerRunException("There are no yara rules selected")
        result = defaultdict(list)
        logger.info(f"Checking {self.public_repositories}")
        number_of_selected_lists = 0
        for url in self.public_repositories:
            result[url] += self.analyze(url)
            logger.info(f"Checking {self.private_repositories}")
            number_of_selected_lists += 1
        for url in self.private_repositories:
            result[url] += self.analyze(url, private=True)
            number_of_selected_lists += 1
        if self.local_rules:
            path = settings.YARA_RULES_PATH / self._job.user.username / "custom_rule"
            result[path] += self._analyze_directory(path)
            number_of_selected_lists += 1
        if self.missing_paths == number_of_selected_lists:
            raise AnalyzerRunException("there was no directory all the selected lists")
        return result

    @classmethod
    def _download_or_update_git_repository(
        cls, url: str, owner: str, ssh_key: str = None
    ) -> PosixPath:
        try:
            if ssh_key:
                ssh_key = ssh_key.replace("-----BEGIN OPENSSH PRIVATE KEY-----", "")
                ssh_key = ssh_key.replace("-----END OPENSSH PRIVATE KEY-----", "")
                ssh_key = ssh_key.strip()
                ssh_key = ssh_key.replace(" ", "\n")
                ssh_key = "-----BEGIN OPENSSH PRIVATE KEY-----\n" + ssh_key
                ssh_key = ssh_key + "\n-----END OPENSSH PRIVATE KEY-----\n"

                with open(settings.GIT_KEY_PATH, "w", encoding="utf_8") as f:
                    f.write(ssh_key)
                logger.info(
                    f"Writing key to download {url} at {str(settings.GIT_KEY_PATH)}"
                )
                os.chmod(settings.GIT_KEY_PATH, 0o600)
                os.environ["GIT_SSH"] = str(settings.GIT_SSH_SCRIPT_PATH)
            directory = cls._get_directory(url, owner)
            logger.info(f"checking {directory=} for {url=} and {owner=}")

            if directory.exists():
                logger.info(f"About to pull {url} at {directory}")
                repo = Repo(directory)
                git = repo.git
                git.config("--add", "safe.directory", directory)
                o = repo.remotes.origin
                o.pull(allow_unrelated_histories=True, rebase=True)
            else:
                logger.info(f"About to clone {url} at {directory}")
                repo = Repo.clone_from(url, directory, depth=1)
                git = repo.git
                git.config("--add", "safe.directory", directory)
            return directory
        finally:
            if ssh_key:
                logger.info("Starting cleanup of git ssh key")
                del os.environ["GIT_SSH"]
                if settings.GIT_KEY_PATH.exists():
                    os.remove(settings.GIT_KEY_PATH)

    @classmethod
    def _get_directory(cls, url: str, owner: str = None) -> PosixPath:
        url_parsed = urlparse(url)
        if url.endswith(".zip"):
            org = url_parsed.netloc
            repo = url_parsed.path.split("/")[-1]
        else:
            path_repo = url_parsed.path.split("/")
            # case git@github.com/ORG/repo.git
            if len(path_repo) == 2:
                org = path_repo[0].split(":")[-1]
                repo = path_repo[1]
            # case https://github.com/ORG/repo
            elif len(path_repo) >= 3:
                org = path_repo[1]
                repo = path_repo[2]
            else:
                raise AnalyzerRunException(f"Unable to update url {url}: malformed")

        # we are removing the .zip, .git. .whatever
        repo = repo.split(".")[0]

        # directory name is organization_repository
        directory_name = "_".join([org, repo]).lower()
        path = (
            settings.YARA_RULES_PATH / str(owner) if owner else settings.YARA_RULES_PATH
        )
        return path / directory_name

    @classmethod
    def _download_or_update_zip_repository(cls, url: str) -> PosixPath:
        directory = cls._get_directory(url)
        logger.info(f"About to download zip file from {url} to {directory}")
        response = requests.get(url, stream=True)
        try:
            response.raise_for_status()
        except Exception as e:
            logger.exception(e)
        else:
            zipfile_ = zipfile.ZipFile(io.BytesIO(response.content))
            zipfile_.extractall(directory)
        return directory

    @classmethod
    def _update_repository(
        cls, url: str, owner: Optional[str] = None, ssh_key: str = None
    ):
        logger.info(f"Starting update of {url}")
        if url.endswith(".zip"):
            # private url not supported at the moment for private
            directory = cls._download_or_update_zip_repository(url)
        else:
            directory = cls._download_or_update_git_repository(
                url, owner, ssh_key=ssh_key
            )
        cls._get_rules.invalidate(cls, directory)

    @classmethod
    def _update(cls):
        logger.info("Starting updating yara rules")
        dict_urls: Dict[Union[None, Tuple[str, str]], Set[str]] = defaultdict(set)
        for analyzer_name, ac in cls.get_config_class().get_from_python_module(cls):
            new_urls = ac.param_values.get("public_repositories", [])
            logger.info(f"Adding configuration urls {new_urls}")
            dict_urls[None].update(new_urls)

            # we are downloading even custom signatures for each analyzer
            for plugin in PluginConfig.objects.filter(
                plugin_name=analyzer_name,
                type=PluginConfig.PluginType.ANALYZER,
                config_type=PluginConfig.ConfigType.PARAMETER,
                attribute="public_repositories",
            ):
                new_urls = plugin.value
                logger.info(f"Adding personal public urls {new_urls}")
                dict_urls[None].update(new_urls)

            for plugin in PluginConfig.objects.filter(
                plugin_name=analyzer_name,
                type=PluginConfig.PluginType.ANALYZER,
                config_type=PluginConfig.ConfigType.SECRET,
                attribute="private_repositories",
            ):
                owner = (
                    f"{plugin.organization.name}.{plugin.organization.owner}"
                    if plugin.organization
                    else plugin.owner.username
                )
                for url, ssh_key in plugin.value.items():
                    logger.info(f"Adding personal private url {url}")
                    dict_urls[(owner, ssh_key)].add(url)
        for owner_ssh_key, urls in dict_urls.items():
            if owner_ssh_key:
                owner, ssh_key = owner_ssh_key
            else:
                owner, ssh_key = None, None
            for url in urls:
                logger.info(f"Going to update {url} yara repo")
                cls._update_repository(url, owner=owner, ssh_key=ssh_key)
        logger.info("Finished updating yara rules")
        set_permissions(settings.YARA_RULES_PATH)
