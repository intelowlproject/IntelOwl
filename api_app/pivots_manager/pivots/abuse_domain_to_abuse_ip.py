import logging
from typing import Any, Optional, Tuple

from api_app.pivots_manager.classes import Pivot

logger = logging.getLogger(__name__)


class AbuseDomainToAbuseIp(Pivot):
    def should_run(self) -> Tuple[bool, Optional[str]]:
        for x in self.related_reports:
            if (
                x.status == self.report_model.Status.SUCCESS.value
                and len(x.report["resolutions"]) > 0
            ):
                logger.info(f"REPORT IS {x.report['resolutions'][0]['data']}")
                value = x.report["resolutions"][0]["data"]
                if value:
                    logger.info(f"VALUE IS {value}")
                    self.value = value
                    result = True
                    break
        else:
            self.value = None
            result = False
        return (
            result,
            f"Necessary reports{'' if result else ' do not'} have success status "
            f"{'and' if result else 'or'} needed data",
        )

    def get_value_to_pivot_to(self) -> Any:
        return self.value
