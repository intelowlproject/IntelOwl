# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import dataclasses
import io
import logging
import os
import zipfile
from pathlib import PosixPath
from typing import Dict, List, Optional
from urllib.parse import urlparse

import requests
import yara
from django.conf import settings
from django.utils.functional import cached_property
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


class YaraStorage:
    class YaraRepo:
        def __init__(
            self,
            url: str,
            owner: str = None,
            key: str = None,
            directory: PosixPath = None,
        ):
            self.url = url
            self.owner = owner
            self.key = key
            self._rules: Optional[yara.Rules] = None
            self._directory = directory

        def __repr__(self):
            return f"{self.owner + ': ' if self.owner else ''}{self.url}"

        @property
        def directory(self) -> PosixPath:
            if not self._directory:
                url_parsed = urlparse(self.url)
                if self.url.endswith(".zip"):
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
                        raise AnalyzerRunException(
                            f"Unable to update url {self.url}: malformed"
                        )

                # we are removing the .zip, .git. .whatever
                repo = repo.split(".")[0]

                # directory name is organization_repository
                directory_name = "_".join([org, repo]).lower()
                path = (
                    settings.YARA_RULES_PATH / str(self.owner)
                    if self.owner
                    else settings.YARA_RULES_PATH
                )
                self._directory = path / directory_name
            return self._directory

        def update(self):
            logger.info(f"Starting update of {self.url}")
            if self.url.endswith(".zip"):
                # private url not supported at the moment for private
                self._update_zip()
            else:
                self._update_git()

        def _update_zip(self):
            logger.info(
                f"About to download zip file from {self.url} to {self.directory}"
            )
            response = requests.get(self.url, stream=True)
            try:
                response.raise_for_status()
            except Exception as e:
                logger.exception(e)
            else:
                zipfile_ = zipfile.ZipFile(io.BytesIO(response.content))
                zipfile_.extractall(self.directory)

        def _update_git(self):
            try:
                if self.key:
                    ssh_key = self.key.replace(
                        "-----BEGIN OPENSSH PRIVATE KEY-----", ""
                    )
                    ssh_key = ssh_key.replace("-----END OPENSSH PRIVATE KEY-----", "")
                    ssh_key = ssh_key.strip()
                    ssh_key = ssh_key.replace(" ", "\n")
                    ssh_key = "-----BEGIN OPENSSH PRIVATE KEY-----\n" + ssh_key
                    ssh_key = ssh_key + "\n-----END OPENSSH PRIVATE KEY-----\n"

                    with open(settings.GIT_KEY_PATH, "w", encoding="utf_8") as f:
                        f.write(ssh_key)
                    logger.info(
                        f"Writing key to download {self.url} "
                        f"at {str(settings.GIT_KEY_PATH)}"
                    )
                    os.chmod(settings.GIT_KEY_PATH, 0o600)
                    os.environ["GIT_SSH"] = str(settings.GIT_SSH_SCRIPT_PATH)
                logger.info(
                    f"checking {self.directory=} for {self.url=} and {self.owner=}"
                )

                if self.directory.exists():
                    self.result_file_name.unlink(missing_ok=True)

                    logger.info(f"About to pull {self.url} at {self.directory}")
                    repo = Repo(self.directory)
                    git = repo.git
                    git.config("--add", "safe.directory", self.directory)
                    o = repo.remotes.origin
                    o.pull(allow_unrelated_histories=True, rebase=True)
                else:
                    logger.info(f"About to clone {self.url} at {self.directory}")
                    repo = Repo.clone_from(self.url, self.directory, depth=1)
                    git = repo.git
                    git.config("--add", "safe.directory", self.directory)
            finally:
                if self.key:
                    logger.info("Starting cleanup of git ssh key")
                    del os.environ["GIT_SSH"]
                    if settings.GIT_KEY_PATH.exists():
                        os.remove(settings.GIT_KEY_PATH)

        @cached_property
        def result_file_name(self) -> PosixPath:
            return self.directory.parent / "intel_owl_compiled.yas"

        @cached_property
        def rules(self):
            if not self._rules:
                if not self.directory.exists():
                    self.update()
                if self.result_file_name.exists():
                    self._rules = yara.load(str(self.result_file_name))
                else:
                    self._rules = self.compile()
            return self._rules

        def compile(self) -> yara.Rules:
            rules = self.directory.rglob("*")
            valid_rules_path = []
            for rule in rules:
                if rule.suffix in [".yara", ".yar", ".rule"]:
                    try:
                        yara.compile(str(rule))
                    except yara.SyntaxError:
                        continue
                    else:
                        valid_rules_path.append(str(rule))
            rule = yara.compile(
                filepaths={str(path): str(path) for path in valid_rules_path}
            )
            compiled_rules = rule.save(str(self.result_file_name))
            return compiled_rules

        def analyze(self, file_path: str, filename: str) -> List[Dict]:
            matches = []
            try:
                matches = self.rules.match(file_path, externals={"filename": filename})
            except yara.Error as e:
                if "internal error" in str(e):
                    _, code = str(e).split(":")
                    if int(code.strip()) == 30:
                        message = f"Too many matches for {filename}"
                        logger.warning(message)
                        matches = [YaraMatchMock(message)]
                else:
                    raise e
            result = []
            for match in matches:
                # limited to 20 strings reasons because it could be a very long list
                result.append(
                    {
                        "match": str(match),
                        "strings": str(match.strings[:20]) if match else "",
                        "tags": match.tags,
                        "meta": match.meta,
                        "path": match.namespace,
                    }
                )
            return result

    def __init__(self):
        self.repos: List = []

    def add_repo(
        self, url: str, owner: str = None, key: str = None, directory: PosixPath = None
    ):
        new_repo = self.YaraRepo(url, owner, key, directory)
        for i, repo in enumerate(self.repos):
            if repo.url == url:
                if owner:
                    if not repo.owner:
                        self.repos[i] = new_repo
                    else:
                        self.repos.append(new_repo)
                return
        self.repos.append(new_repo)

    def compile(self):
        for repo in self.repos:
            repo.compile("intel_owl_compiled.yas")

    def analyze(self, file_path: str, filename: str) -> Dict:
        result = {}
        for repo in self.repos:
            result[str(repo.directory.name)] = repo.analyze(file_path, filename)
            # free some memory
            repo._rules = None
        return result

    def __repr__(self):
        return self.repos.__repr__()


class YaraScan(FileAnalyzer):

    IGNORE_DIRECTORIES = [".git", ".github"]

    def set_params(self, params):
        self.ignore_rules = params.get("ignore", [])
        self.repositories = params.get("repositories", [])
        self.private_repositories = self._secrets.get("private_repositories", {})
        self.local_rules = params.get("local_rules", False)

    def run(self):
        if not self.repositories:
            raise AnalyzerRunException("There are no yara rules selected")
        storage = YaraStorage()
        for url in self.repositories:
            if url in self.private_repositories.keys():
                try:
                    PluginConfig.objects.get(
                        plugin_name=self.analyzer_name,
                        type=PluginConfig.PluginType.ANALYZER,
                        config_type=PluginConfig.ConfigType.SECRET,
                        attribute="private_repositories",
                        user=self._job.user,
                    )
                except PluginConfig.DoesNotExist:
                    if self._job.user.has_membership():
                        owner = (
                            f"{self._job.user.organization.name}"
                            f".{self._job.user.organization.owner}"
                        )
                    else:
                        raise AnalyzerRunException(f"Unable to find repository {url}")
                else:
                    owner = self._job.user.username
                key = self.private_repositories[url]
            else:
                owner = None
                key = None
            storage.add_repo(url, owner, key)
        if self.local_rules:
            path: PosixPath = (
                settings.YARA_RULES_PATH / self._job.user.username / "custom_rule"
            )
            if path.exists():
                storage.add_repo(
                    "",
                    directory=settings.YARA_RULES_PATH
                    / self._job.user.username
                    / "custom_rule",
                )
        return storage.analyze(self.filepath, self.filename)

    @classmethod
    def _create_storage(cls):
        storage = YaraStorage()
        for analyzer_name, ac in cls.get_config_class().get_from_python_module(cls):
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
                    storage.add_repo(url, owner, ssh_key)

            new_urls = ac.param_values.get("repositories", [])
            logger.info(f"Adding configuration urls {new_urls}")
            for url in new_urls:
                storage.add_repo(url)

            # we are downloading even custom signatures for each analyzer
            for plugin in PluginConfig.objects.filter(
                plugin_name=analyzer_name,
                type=PluginConfig.PluginType.ANALYZER,
                config_type=PluginConfig.ConfigType.PARAMETER,
                attribute="repositories",
            ):
                new_urls = plugin.value
                logger.info(f"Adding personal urls {new_urls}")
                for url in new_urls:
                    storage.add_repo(url)
        return storage

    @classmethod
    def _update(cls):
        logger.info("Starting updating yara rules")
        storage = cls._create_storage()
        logger.info(f"Urls are {storage}")
        for repo in storage.repos:
            repo: YaraStorage.YaraRepo
            logger.info(f"Going to update {repo.url} yara repo")
            repo.update()
            repo.compile()
        logger.info("Finished updating yara rules")
        set_permissions(settings.YARA_RULES_PATH)
