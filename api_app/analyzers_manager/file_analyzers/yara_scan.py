# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import io
import json
import logging
import os
import zipfile
from collections import defaultdict
from pathlib import PosixPath
from typing import Dict, List, Optional, Set, Tuple, Union
from urllib.parse import urlparse

import requests
import yara
from cache_memoize import cache_memoize
from django.conf import settings
from git import Repo

from api_app.analyzers_manager.classes import FileAnalyzer
from api_app.analyzers_manager.dataclasses import AnalyzerConfig
from api_app.exceptions import AnalyzerRunException
from api_app.models import PluginConfig
from certego_saas.apps.organization.membership import Membership
from intel_owl.settings._util import set_permissions

logger = logging.getLogger(__name__)


def export_ssh_key(function):
    def wrapper(*args, ssh_key: str = None, **kwargs):
        if ssh_key:
            ssh_key = ssh_key.replace("-----BEGIN OPENSSH PRIVATE KEY-----", "")
            ssh_key = ssh_key.replace("-----END OPENSSH PRIVATE KEY-----", "")
            ssh_key = ssh_key.strip()
            ssh_key = ssh_key.replace(" ", "\n")
            ssh_key = "-----BEGIN OPENSSH PRIVATE KEY-----\n" + ssh_key
            ssh_key = ssh_key + "\n-----END OPENSSH PRIVATE KEY-----\n"

            logger.info("Writing key")
            with open(settings.GIT_KEY_PATH, "w", encoding="utf_8") as f:
                f.write(ssh_key)
            os.chmod(settings.GIT_KEY_PATH, 0o600)
            os.environ["GIT_SSH"] = str(settings.GIT_SSH_SCRIPT_PATH)
        try:
            return function(*args, **kwargs)
        finally:
            if ssh_key:
                del os.environ["GIT_SSH"]
                os.remove(settings.GIT_KEY_PATH)
    return wrapper


class YaraScan(FileAnalyzer):
    def set_params(self, params):
        self.ignore_rules = params.get("ignore", [])
        self.public_repositories = params.get("public_repositories", [])
        self.private_repositories = list(
            json.loads(self._secrets.get("private_repositories", "{}")).keys()
        )

    def _load_directory(
        self, rulepath: PosixPath
    ) -> List[Tuple[PosixPath, yara.Rules]]:
        logger.info(f"Loading directory {rulepath}")
        rules = []
        if rulepath.name == ".git":
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
            return rules.match(self.filepath)
        except yara.Error as e:
            if "internal error" in str(e):
                _, code = str(e).split(":")
                if int(code.strip()) == 30:
                    message = f"Too many matches for {self.filename}"
                    logger.warning(message)
                    return [{"match": message}]
            raise e

    def _compile_rule(self, file_path: PosixPath) -> Optional[yara.Rules]:
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

    @cache_memoize(
        timeout=60 * 60 * 24,
        args_rewrite=lambda s, directory_path: f"{s.__class__.__name__}"
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

    def analyze(self, url: str, private: bool = False):
        result = []
        if private:
            # private rules are downloaded in the user directory
            directory = self._get_directory(url, self._job.user.username)
            # or, if are set at organization level, in the organization owner directory
            if not directory.exists():
                try:
                    membership = Membership.objects.get(user=self._job.user)
                except Membership.DoesNotExist:
                    # user has no org,
                    # he is trying to access a repo that he does not own
                    raise AnalyzerRunException(
                        f"There are no rules downloaded for {url}"
                    )
                else:
                    owner = (
                        f"{membership.organization.name}."
                        f"{membership.organization.owner}"
                    )
                    directory = self._get_directory(url, owner)
        else:
            directory = self._get_directory(url)

        if not directory.exists():
            raise AnalyzerRunException(f"There are no rules downloaded for {url}")

        logger.info(f"Getting rules inside {directory}")
        list_rules_compiled = self._get_rules(directory)
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

    def run(self):
        if not self.public_repositories and not self.private_repositories:
            raise AnalyzerRunException("There are no yara rules selected")
        result = []
        logger.info(f"Checking {self.public_repositories}")
        for url in self.public_repositories:
            result += self.analyze(url)
            logger.info(f"Checking {self.private_repositories}")
        for url in self.private_repositories:
            result += self.analyze(url, private=True)
        return result

    @classmethod
    @export_ssh_key
    def _download_or_update_git_repository(cls, url: str, owner: str):
        directory = cls._get_directory(url, owner)

        if not directory.exists():
            logger.info(f"About to clone {url} at {directory}")
            Repo.clone_from(url, directory, depth=1)
        else:
            logger.info(f"about to pull {url} at {directory}")
            repo = Repo(directory)
            git = repo.git
            git.config("--global", "--add", "safe.directory", directory)
            o = repo.remotes.origin
            o.pull(allow_unrelated_histories=True, rebase=True)

    @classmethod
    def _get_directory(cls, url: str, owner: str = None) -> PosixPath:
        if url.endswith(".zip"):
            url_parsed = urlparse(url)
            org = url_parsed.netloc
            # get the last path + remove .zip
            repo = url_parsed.path.split("/")[-1].split(".")[0]
        else:
            url_list = url.split("/")
            # remove the git@github: if present
            org = url_list[-2].split(":")[-1]
            # we are removing the .zip, .git. .whatever
            repo = url_list[-1].split(".")[0]

        # directory name is organization_repository
        directory_name = "_".join([org, repo]).lower()
        path = (
            settings.YARA_RULES_PATH / str(owner) if owner else settings.YARA_RULES_PATH
        )
        return path / directory_name

    @classmethod
    def _download_or_update_zip_repository(cls, url: str):
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

    @classmethod
    def _update_repository(
        cls, url: str, owner: Optional[str] = None, ssh_key: str = None
    ):
        if url.endswith(".zip"):
            # private url not supported at the moment for private
            cls._download_or_update_zip_repository(url)
        else:
            cls._download_or_update_git_repository(url, owner, ssh_key=ssh_key)

    @classmethod
    def update_rules(cls):
        logger.info("Starting updating yara rules")
        analyzer_config = AnalyzerConfig.all()
        dict_urls: Dict[Union[None, Tuple[str, str]], Set[str]] = defaultdict(set)
        for analyzer_name, ac in analyzer_config.items():
            if (
                ac.python_module == f"{cls.__module__.split('.')[-1]}.{cls.__name__}"
                and ac.disabled is False
            ):
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
                    try:
                        value = json.loads(plugin.value)
                    except json.JSONDecodeError:
                        value = plugin.value
                    for url, ssh_key in value.items():
                        logger.info(f"Adding personal private url {url}")
                        dict_urls[(owner, ssh_key)].add(url)
            else:
                logger.info(f"Skipping analyzer {analyzer_name}")
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
