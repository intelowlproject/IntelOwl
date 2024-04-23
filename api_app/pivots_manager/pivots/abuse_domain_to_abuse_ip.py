import logging
from typing import Any, Optional, Tuple

from api_app.pivots_manager.classes import Pivot
from api_app.playbooks_manager.models import PlaybookConfig

logger = logging.getLogger(__name__)


class AbuseDomainToAbuseIp(Pivot):
    def should_run(self) -> Tuple[bool, Optional[str]]:
        playbook = PlaybookConfig.objects.filter(name="Abuse_Domain").first()
        self.value = None
        result = False
        if self._job.playbook_requested == playbook:
            for x in self.related_reports:
                if (
                    x.status == self.report_model.Status.SUCCESS.value
                    and len(x.report["resolutions"]) > 0
                ):
                    value = x.report["resolutions"][0]["data"]
                    if value:
                        self.value = value
                        result = True
                        break
        return (
            result,
            f"Necessary reports{'' if result else ' do not'} have success status "
            f"{'and' if result else 'or'} needed data",
        )

    def get_value_to_pivot_to(self) -> Any:
        return self.value

    def update(self) -> bool:
        pass
