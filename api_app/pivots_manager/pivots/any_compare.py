import logging
from typing import Optional, Tuple

from api_app.pivots_manager.pivots.compare import Compare

logger = logging.getLogger(__name__)


class AnyCompare(Compare):
    def should_run(self) -> Tuple[bool, Optional[str]]:
        for report in self.related_reports.filter(status=self.report_model.STATUSES.SUCCESS.value):
            try:
                self._value = report.get_value(report.report, self.field_to_compare.split("."))
            except (RuntimeError, ValueError):
                continue
            else:
                return True, "Key found with success"

        return (
            False,
            f"Field {self.field_to_compare} not found in success reports",
        )

    def update(self) -> bool:
        pass
