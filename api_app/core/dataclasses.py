# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
from abc import abstractmethod
import typing
import dataclasses

from intel_owl import secrets as secrets_store


# constants
DEFAULT_QUEUE = "default"
DEFAULT_SOFT_TIME_LIMIT = 300


@dataclasses.dataclass
class _SecretsVerification:
    configured: bool
    error_message: str
    missing_secrets: typing.List


@dataclasses.dataclass
class _ConfigParams:
    queue: str = DEFAULT_QUEUE
    soft_time_limit: int = DEFAULT_SOFT_TIME_LIMIT


@dataclasses.dataclass
class AbstractConfig:
    name: str
    python_module: str
    disabled: bool
    description: str
    config: dict
    secrets: dict
    verification: _SecretsVerification

    def __post_init__(self):
        # for nested dataclasses
        if isinstance(self.verification, dict):
            self.verification = _SecretsVerification(**self.verification)

    # utils

    @property
    def params(self) -> _ConfigParams:
        if not hasattr(self, "__cached_config_params"):
            self.__cached_config_params = _ConfigParams(
                queue=self.config.get("queue", DEFAULT_QUEUE),
                soft_time_limit=self.config.get(
                    "soft_time_limit", DEFAULT_SOFT_TIME_LIMIT
                ),
            )

        return self.__cached_config_params

    @property
    def is_configured(self) -> bool:
        return self.verification.configured

    @property
    def is_ready_to_use(self) -> bool:
        return not self.disabled and self.verification.configured

    def asdict(self) -> dict:
        if not hasattr(self, "__cached_dict"):
            self.__cached_dict = dataclasses.asdict(self)

        return self.__cached_dict

    def _read_secrets(self, secrets_filter=[]) -> dict:
        """
        Returns a dict of `secret_key: secret_value` mapping.
        filter_secrets: filter specific secrets or not (default: return all)
        """
        secrets = {}
        if len(secrets_filter):
            _filtered_secrets = {
                key_name: self.secrets[key_name]
                for key_name in self.secrets.keys()
                if key_name in secrets_filter
            }
        else:
            _filtered_secrets = self.secrets
        for key_name, secret_dict in _filtered_secrets.items():
            secret_val = secrets_store.get_secret(secret_dict["env_var_key"])
            if secret_val:
                secrets[key_name] = secret_val
            else:
                secrets[key_name] = secret_dict["default"]

        return secrets

    @abstractmethod
    def get_full_import_path(self) -> str:
        raise NotImplementedError()
