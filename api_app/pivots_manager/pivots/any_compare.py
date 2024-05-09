import logging
from typing import Optional, Tuple

from api_app.pivots_manager.pivots.compare import Compare

logger = logging.getLogger(__name__)


class AnyCompare(Compare):
    def should_run(self) -> Tuple[bool, Optional[str]]:
        if result := self.related_reports.filter(
            status=self.report_model.Status.SUCCESS.value
        ).first():
            try:
                self._value = self._get_value(self.field_to_compare)
            except (RuntimeError, ValueError) as e:
                return False, str(e)
        return (
            bool(result),
            f"All necessary reports{'' if result else ' do not'} have success status",
        )

    def update(self) -> bool:
        pass
