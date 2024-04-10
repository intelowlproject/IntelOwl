import logging
from typing import Any, Optional, Tuple

from api_app.pivots_manager.classes import Pivot

logger = logging.getLogger(__name__)


class AbuseIpToSubmission(Pivot):
    def should_run(self) -> Tuple[bool, Optional[str]]:
        for x in self.related_reports:
            if (
                x.status == self.report_model.Status.SUCCESS.value
                and len(x.report["abuse_contacts"]) > 0
            ):
                value = x.report["abuse_contacts"][0]
                if value:
                    self.value = value
                    result = True
                    break
        else:
            self.value = None
            result = False
        return (
            result,
            f"Abuse contacts {'' if result else 'not'} found",
        )

    def get_value_to_pivot_to(self) -> Any:
        return self.value
