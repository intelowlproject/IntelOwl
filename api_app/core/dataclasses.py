# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import dataclasses
import typing
from abc import abstractmethod

from intel_owl import secrets as secrets_store
from intel_owl.consts import (
    DEFAULT_QUEUE,
    DEFAULT_SOFT_TIME_LIMIT,
    PARAM_DATATYPE_CHOICES,
)


@dataclasses.dataclass
class _SecretsVerification:
    configured: bool
    error_message: typing.Optional[str]
    missing_secrets: typing.List


@dataclasses.dataclass
class _Config:
    queue: str = DEFAULT_QUEUE
    soft_time_limit: int = DEFAULT_SOFT_TIME_LIMIT


@dataclasses.dataclass
class _Param:
    value: typing.Any
    type: typing.Literal[PARAM_DATATYPE_CHOICES]
    description: str


@dataclasses.dataclass
class _Secret:
    env_var_key: str
    description: str
    required: bool


@dataclasses.dataclass
class AbstractConfig:
    name: str
    python_module: str
    disabled: bool
    description: str
    secrets: typing.Dict[str, _Secret]
    params: typing.Dict[str, _Param]
    config: _Config
    verification: _SecretsVerification

    def __post_init__(self):
        secrets_values = list(self.secrets.values())
        params_values = list(self.params.values())
        # for nested dataclasses
        if isinstance(self.verification, dict):
            self.verification = _SecretsVerification(**self.verification)
        if isinstance(self.config, dict):
            self.config = _Config(**self.config)
        if params_values and isinstance(params_values[0], dict):
            self.params = {
                pname: _Param(**pdict) for pname, pdict in self.params.items()
            }
        if secrets_values and isinstance(secrets_values[0], dict):
            self.secrets = {
                sname: _Secret(**sdict) for sname, sdict in self.secrets.items()
            }

    # utils

    @property
    def is_configured(self) -> bool:
        return self.verification.configured

    @property
    def is_ready_to_use(self) -> bool:
        return not self.disabled and self.verification.configured

    @property
    def param_values(self) -> dict:
        return {name: param.value for name, param in self.params.items()}

    def _read_secrets(self, secrets_filter=None) -> typing.Dict[str, str]:
        """
        Returns a dict of `secret_key: secret_value` mapping.
        filter_secrets: filter specific secrets or not (default: return all)
        """
        if secrets_filter is None:
            secrets_filter = []
        secrets = {}
        if secrets_filter:
            _filtered_secrets = {
                key_name: self.secrets[key_name]
                for key_name in self.secrets.keys()
                if key_name in secrets_filter
            }
        else:
            _filtered_secrets = self.secrets
        for key_name, secret in _filtered_secrets.items():
            secrets[key_name] = secrets_store.get_secret(
                secret.env_var_key, default=None
            )

        return secrets

    @abstractmethod
    def get_full_import_path(self) -> str:
        raise NotImplementedError()

    # dataclass functionality extension

    @classmethod
    @abstractmethod
    def from_dict(cls, data: dict):
        raise NotImplementedError()

    def asdict(self) -> dict:
        return dataclasses.asdict(self)

    # orm methods

    @classmethod
    @abstractmethod
    def get(cls, name: str) -> typing.Optional["AbstractConfig"]:
        """
        Returns config dataclass by name if found, else None
        """
        raise NotImplementedError()

    @classmethod
    @abstractmethod
    def all(cls):
        raise NotImplementedError()

    @classmethod
    @abstractmethod
    def filter(cls, names: typing.List[str]):
        raise NotImplementedError()
