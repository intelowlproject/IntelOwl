from typing import Any

from django.core.files import File

from api_app.pivots_manager.classes import Pivot


class SelfAnalyzable(Pivot):
    def should_run(self) -> bool:
        return True

    def get_value_to_pivot_to(self) -> Any:
        obj = self._job.analyzed_object
        # the 7 is because the file name follow this syntax
        # `f"job_{now}_{filename}"` where
        # `now = timezone.now().strftime("%Y_%m_%d_%H_%M_%S")`
        # meaning that the real filename is actually after 7 underscores
        name = "_".join(obj.name.split("_")[7:])

        return File(obj, name=name)
