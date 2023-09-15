from typing import Any

from api_app.pivots_manager.classes import Pivot
from api_app.pivots_manager.exceptions import PivotFieldNotFoundException


class Compare(Pivot):
    value_to_compare: Any

    def before_run(self):
        value_found = super().before_run()
        if value_found != self.value_to_compare:
            raise PivotFieldNotFoundException("Value")

    def run(self) -> Any:
        return self.get_value(self._config.field_to_compare)
