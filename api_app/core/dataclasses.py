# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import typing
import dataclasses

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
