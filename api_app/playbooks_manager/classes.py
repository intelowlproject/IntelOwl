# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
from typing import Optional

from api_app.core.classes import Plugin

from ..exceptions import PlaybookConfigurationException, PlaybookRunException
from .dataclasses import PlaybookConfig
from .models import PlaybookReport

logger = logging.getLogger(__name__)

class Playbook(Plugin):
    """
    Abstract class for all Playbooks.
    Inherit from this if needed to define custom playbook logic.
    """
    
    @property
    def playbook_name(self) -> str:
        return self._config.name

    @property
    def report_model(self):
        return PlaybookReport
    
    def get_exceptions_to_catch(self) -> list:
        return [
            PlaybookConfigurationException,
            PlaybookRunException
        ]
    
    def get_error_message(self, err, is_base_err=False):
        return (
            f"{self.__repr__()}."
            f" {'Unexpected error' if is_base_err else 'Playbook error'}: '{err}'"
        )
    
    def before_run(self):
        logger.info(f"STARTED playbook: {self.__repr__()}")

    def after_run(self):
        logger.info(f"FINISHED playbook: {self.__repr__()}")
    
    def __repr__(self):
        return f"({self.playbook_name}, job: #{self.job_id})"
    
    # Implement a healthcheck IF necessary.





































  