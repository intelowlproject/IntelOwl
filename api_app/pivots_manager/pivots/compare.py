from typing import Any, Optional, Tuple

from api_app.pivots_manager.classes import Pivot


class Compare(Pivot):
    field_to_compare: str

    @classmethod
    def update(cls) -> bool:
        pass

    def should_run(self) -> Tuple[bool, Optional[str]]:
        if self.related_reports.count() != 1:
            return (
                False,
                f"Unable to run pivot {self._config.name} "
                "because attached to more than one configuration",
            )
        try:
            self._value = self.related_reports.first().get_value(self.field_to_compare)
        except (RuntimeError, ValueError) as e:
            return False, str(e)
        return super().should_run()

    def get_value_to_pivot_to(self) -> Any:
        return self._value
