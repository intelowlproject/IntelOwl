from typing import Optional, Tuple

from api_app.pivots_manager.classes import Pivot


class AbuseDomainToAbuseIp(Pivot):
    def should_run(self) -> Tuple[bool, Optional[str]]:
        result = any(
            x.status == self.report_model.Status.SUCCESS.value
            for x in self.related_reports
        )
        return (
            result,
            f"All necessary reports{'' if result else ' do not'} have success status",
        )
