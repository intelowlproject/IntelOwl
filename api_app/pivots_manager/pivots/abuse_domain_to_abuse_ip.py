import logging
from typing import Any, Optional, Tuple

from api_app.pivots_manager.classes import Pivot
from api_app.playbooks_manager.models import PlaybookConfig

logger = logging.getLogger(__name__)


class AbuseDomainToAbuseIp(Pivot):
    def should_run(self) -> Tuple[bool, Optional[str]]:
        if valid_report := self.related_reports.filter(status=self.report_model.Status.SUCCESS.value).first():
            self._value = valid_report.report["resolutions"] # etc
             result = True

    def get_value_to_pivot_to(self) -> Any:
        return self.value

    def update(self) -> bool:
        pass
