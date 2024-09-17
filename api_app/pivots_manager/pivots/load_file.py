import base64
from typing import Any, List

from api_app.pivots_manager.pivots.compare import Compare


class LoadFile(Compare):
    field_to_compare: str

    @classmethod
    def update(cls) -> bool:
        pass

    def get_value_to_pivot_to(self) -> Any:
        if isinstance(self._value, List):
            for v in self._value:
                if isinstance(v, (bytes, bytearray, str)):
                    yield base64.b64decode(v)
                else:
                    raise ValueError("Invalid data type to base64 decode")
        elif isinstance(self._value, (bytes, bytearray, str)):
            yield base64.b64decode(self._value)
        else:
            raise ValueError("Invalid data type to base64 decode")
