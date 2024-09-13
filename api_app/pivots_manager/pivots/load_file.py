import base64
from typing import Any

from api_app.pivots_manager.pivots.compare import Compare


class LoadFile(Compare):
    field_to_compare: str

    @classmethod
    def update(cls) -> bool:
        pass

    def get_value_to_pivot_to(self) -> Any:
        return base64.b64decode(self._value)
