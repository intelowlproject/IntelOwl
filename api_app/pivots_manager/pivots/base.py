from typing import Any

from api_app.pivots_manager.classes import Pivot


class Base(Pivot):
    def run(self) -> Any:
        return self.get_value(self._config.field_to_compare)
