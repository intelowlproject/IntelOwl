# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import dataclasses
import io
import logging
import math
import os
import zipfile
from pathlib import PosixPath
from typing import Dict, List, Optional, Tuple, Union
from urllib.parse import urlparse

import git
import requests
import yara
from django.conf import settings
from django.utils.functional import cached_property

from api_app.analyzers_manager.classes import FileAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.models import Parameter, PluginConfig
from intel_owl.settings._util import set_permissions

logger = logging.getLogger(__name__)

MAX_YARA_STRINGS = 20
yara.set_config(max_strings_per_rule=MAX_YARA_STRINGS)


@dataclasses.dataclass
class YaraMatchMock:
    match: str
    strings: List = dataclasses.field(default_factory=list)
    tags: List = dataclasses.field(default_factory=list)
    meta: Dict = dataclasses.field(default_factory=dict)

    def __str__(self):
        return self.match


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
        self._rules: List[yara.Rules] = []
        self._directory = directory

    def __repr__(self):
        return f"{self.owner + ': ' if self.owner else ''}{self.url}@{self.directory}"

    @property
    def directory(self) -> PosixPath:
        if not self._directory:
            url_parsed = urlparse(self.url)
            if self.is_zip():
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
                    raise AnalyzerRunException(f"Unable to update url {self.url}: malformed")

            # we are removing the .zip, .git. .whatever
            repo = repo.split(".")[0]

            # directory name is organization_repository
            directory_name = "_".join([org, repo]).lower()
            path = settings.YARA_RULES_PATH / str(self.owner) if self.owner else settings.YARA_RULES_PATH
            self._directory = path / directory_name
        return self._directory

    def update(self):
        logger.info(f"Starting update of {self.url}")
        if self.is_zip():
            # private url not supported at the moment for private
            self._update_zip()
        else:
            self._update_git()

    def _update_zip(self):
        logger.info(f"About to download zip file from {self.url} to {self.directory}")
        response = requests.get(self.url, stream=True)
        try:
            response.raise_for_status()
        except Exception as e:
            logger.exception(e)
            os.makedirs(self.directory, exist_ok=True)  # still create the folder or raise errors
        else:
            zipfile_ = zipfile.ZipFile(io.BytesIO(response.content))
            zipfile_.extractall(self.directory)

    def _update_git(self):
        try:
            if self.key:
                ssh_key = self.key.replace("-----BEGIN OPENSSH PRIVATE KEY-----", "")
                ssh_key = ssh_key.replace("-----END OPENSSH PRIVATE KEY-----", "")
                ssh_key = ssh_key.strip()
                ssh_key = ssh_key.replace(" ", "\n")
                ssh_key = "-----BEGIN OPENSSH PRIVATE KEY-----\n" + ssh_key
                ssh_key = ssh_key + "\n-----END OPENSSH PRIVATE KEY-----\n"

                with open(settings.GIT_KEY_PATH, "w", encoding="utf_8") as f:
                    f.write(ssh_key)
                logger.info(f"Writing key to download {self.url} at {str(settings.GIT_KEY_PATH)}")
                os.chmod(settings.GIT_KEY_PATH, 0o600)
                os.environ["GIT_SSH"] = str(settings.GIT_SSH_SCRIPT_PATH)
            logger.info(f"checking {self.directory=} for {self.url=} and {self.owner=}")

            if self.directory.exists():
                # this is to allow a clean pull
                for compiled_file in self.compiled_paths:
                    compiled_file.unlink(missing_ok=True)

                logger.info(f"About to pull {self.url} at {self.directory}")
                repo = git.Repo(self.directory)
                o = repo.remotes.origin
                try:
                    o.pull(allow_unrelated_histories=True, rebase=True)
                except git.exc.GitCommandError as e:
                    if "index.lock" in e.stderr:
                        # for some reason the git process did not exit correctly
                        self.delete_lock_file()
                        o.pull(allow_unrelated_histories=True, rebase=True)
                    else:
                        logger.exception(e)
                        return
            else:
                logger.info(f"About to clone {self.url} at {self.directory}")
                git.Repo.clone_from(self.url, self.directory, depth=1)
        finally:
            if self.key:
                logger.info("Starting cleanup of git ssh key")
                del os.environ["GIT_SSH"]
                if settings.GIT_KEY_PATH.exists():
                    os.remove(settings.GIT_KEY_PATH)

    def delete_lock_file(self):
        lock_file_path = self.directory / ".git" / "index.lock"
        lock_file_path.unlink(missing_ok=False)

    @property
    def compiled_file_name(self):
        return "intel_owl_compiled.yas"

    @cached_property
    def first_level_directories(self) -> List[PosixPath]:
        paths = []
        if self.directory.exists():
            for directory in self.directory.iterdir():
                if directory.is_dir() and directory.stem not in [".git", ".github"]:
                    paths.append(directory)
        return paths

    @cached_property
    def compiled_paths(self) -> List[PosixPath]:
        return [path / self.compiled_file_name for path in self.first_level_directories + [self.directory]]

    def is_zip(self):
        return self.url.endswith(".zip")

    @cached_property
    def head_branch(self) -> str:
        return git.Repo(self.directory).head.ref.name

    @property
    def rules(self) -> List[yara.Rules]:
        if not self._rules:
            if not self.directory.exists():
                self.update()
            for compiled_path in self.compiled_paths:
                if compiled_path.exists():
                    self._rules.append(yara.load(str(compiled_path)))
                else:
                    self._rules = self.compile()
                    break
        return self._rules

    def rule_url(self, namespace: str) -> Optional[str]:
        if self.is_zip():
            return None
        namespace = PosixPath(namespace)
        if namespace.is_relative_to(self.directory):
            relative_part = PosixPath(str(namespace).replace(str(self.directory), ""))
            url = self.url[:-4] if self.url.endswith(".git") else self.url
            return f"{url}/blob/{self.head_branch}{relative_part}"
        else:
            logger.error(f"Unable to calculate url from {namespace}")
        return None

    def compile(self) -> List[yara.Rules]:
        logger.info(f"Starting compile for {self}")
        compiled_rules = []

        for directory in self.first_level_directories + [self.directory]:
            if directory != self.directory:
                # recursive
                rules = directory.rglob("*")
            else:
                # not recursive
                rules = directory.glob("*")
            valid_rules_path = []
            for rule in rules:
                if rule.stem.endswith("index") or rule.stem.startswith("index"):
                    continue
                if rule.suffix in [".yara", ".yar", ".rule"]:
                    try:
                        yara.compile(str(rule))
                    except yara.SyntaxError:
                        continue
                    else:
                        valid_rules_path.append(str(rule))
            logger.info(f"Compiling {len(valid_rules_path)} rules for {self} at {directory}")
            compiled_rule = yara.compile(filepaths={str(path): str(path) for path in valid_rules_path})
            compiled_rule.save(str(directory / self.compiled_file_name))
            compiled_rules.append(compiled_rule)
            logger.info(f"Rules {self} saved on file")
        return compiled_rules

    def analyze(self, file_path: str, filename: str) -> List[Dict]:
        logger.info(f"{self} starting analysis of {filename} for file path {file_path}")
        result = []
        for rule in self.rules:
            rule: yara.Match
            try:
                matches = rule.match(file_path, externals={"filename": filename})
            except yara.Error as e:
                if "internal error" in str(e):
                    _, code = str(e).split(":")
                    if int(code.strip()) == 30:
                        message = f"Too many matches for {filename}"
                        logger.warning(message)
                        matches = [YaraMatchMock(message)]
                    else:
                        raise e
                else:
                    raise e

            for match in matches:
                logger.info(f"{self} analyzing strings analysis of {filename} for match {match}")
                strings = []
                # limited to 20 strings reasons because it could be a very long list
                for string in match.strings[:20]:
                    string: yara.StringMatch
                    entry = {
                        "identifier": string.identifier,
                        "plaintext": [str(i) for i in string.instances[:20]],
                    }
                    strings.append(entry)
                    logger.debug(f"{strings=}")

                logger.info(f"{self} found {len(strings)} strings for {filename}for match {match}")
                result.append(
                    {
                        "match": str(match),
                        "strings": strings,
                        "tags": match.tags,
                        "meta": match.meta,
                        "path": match.namespace,
                        "url": self.url,
                        "rule_url": self.rule_url(match.namespace),
                    }
                )
        return result


class YaraStorage:
    def __init__(self):
        self.repos: List[YaraRepo] = []

    def add_repo(self, url: str, owner: str = None, key: str = None, directory: PosixPath = None):
        new_repo = YaraRepo(url, owner, key, directory)
        for i, repo in enumerate(self.repos):
            if repo.url == url:
                if owner:
                    if not repo.owner:
                        self.repos[i] = new_repo
                    else:
                        self.repos.append(new_repo)
                return
        self.repos.append(new_repo)

    def analyze(self, file_path: str, filename: str) -> Dict:
        result = {}
        errors = []
        for repo in self.repos:
            try:
                result[str(repo.directory.name)] = repo.analyze(file_path, filename)
                # free some memory
                repo._rules = []
            except Exception as e:
                logger.warning(f"{filename} rules analysis failed: {e}", stack_info=True)
                errors.append(str(e))
        return result, errors

    def __repr__(self):
        return self.repos.__repr__()


class YaraScan(FileAnalyzer):
    ignore: list
    repositories: list
    _private_repositories: dict = {}
    local_rules: str

    def _get_owner_and_key(self, url: str) -> Tuple[Union[str, None], Union[str, None]]:
        if url in self._private_repositories:
            parameter: Parameter = (
                Parameter.objects.filter(
                    python_module=self.python_module,
                    is_secret=True,
                    name="private_repositories",
                )
                .annotate_configured(self._config, self._job.user)
                .annotate_value_for_user(self._config, self._job.user)
                .first()
            )
            if parameter and parameter.configured and parameter.value and parameter.is_from_org:
                if self._job.user.has_membership():
                    owner = (
                        f"{self._job.user.membership.organization.name}"
                        f".{self._job.user.membership.organization.owner}"
                    )
                else:
                    raise AnalyzerRunException(f"Unable to find repository {url}")
            else:
                owner = self._job.user.username
            key = self._private_repositories[url]
        else:
            owner = None
            key = None
        return owner, key

    def run(self):
        if not self.repositories:
            raise AnalyzerRunException("There are no yara rules selected")
        storage = YaraStorage()
        for url in self.repositories:
            owner, key = self._get_owner_and_key(url)
            storage.add_repo(url, owner, key)
        if self.local_rules:
            path: PosixPath = settings.YARA_RULES_PATH / self._job.user.username / "custom_rule"
            if path.exists():
                storage.add_repo(
                    "",
                    directory=settings.YARA_RULES_PATH / self._job.user.username / "custom_rule",
                )
        report, errors = storage.analyze(self.filepath, self.filename)
        if errors:
            self.report.errors.extend(errors)
            self.report.save()
        return report

    @classmethod
    def _create_storage(cls):
        storage = YaraStorage()

        for plugin in PluginConfig.objects.filter(
            parameter__name="private_repositories",
            parameter__python_module=cls.python_module,
        ):
            if not plugin.value:
                continue
            owner = (
                f"{plugin.organization.name}.{plugin.organization.owner}"
                if plugin.for_organization
                else plugin.owner.username
            )
            for url, ssh_key in plugin.value.items():
                logger.info(f"Adding personal private url {url}")
                storage.add_repo(url, owner, ssh_key)

        # we are downloading even custom signatures for each analyzer
        for plugin in PluginConfig.objects.filter(
            parameter__name="repositories", parameter__python_module=cls.python_module
        ):
            new_urls = plugin.value
            logger.info(f"Adding personal urls {new_urls}")
            for url in new_urls:
                storage.add_repo(url)
        return storage

    @classmethod
    def update(cls):
        logger.info("Starting updating yara rules")
        storage = cls._create_storage()
        logger.info(f"Urls are {storage}")
        for repo in storage.repos:
            logger.info(f"Going to update {repo.url} yara repo")
            repo.update()
            repo.compile()
        logger.info("Finished updating yara rules")
        set_permissions(settings.YARA_RULES_PATH)
        return True

    def _create_data_model_mtm(self):
        from api_app.data_model_manager.models import Signature

        signatures = []
        for yara_signatures in self.report.report.values():
            for yara_signature in yara_signatures:
                url = yara_signature.pop("rule_url", None)
                sign = Signature.objects.create(
                    provider=Signature.PROVIDERS.YARA.value,
                    signature=yara_signature,
                    url=url if url else "",
                    score=1,
                )
                signatures.append(sign)

        return {"signatures": signatures}

    def _update_data_model(self, data_model):
        from api_app.data_model_manager.models import FileDataModel

        super()._update_data_model(data_model)
        data_model: FileDataModel
        signatures = data_model.signatures.count()

        if signatures:
            data_model.evaluation = self.EVALUATIONS.MALICIOUS.value
            data_model.reliability = min(math.floor(signatures / 2), 10)
        else:
            data_model.evaluation = self.EVALUATIONS.TRUSTED.value
            data_model.reliability = 3
