import os
from typing import Any, Optional, Tuple

from api_app.pivots_manager.pivots.compare import Compare


class LoadFile(Compare):
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
            self._value = self._get_value(self.field_to_compare)
        except (RuntimeError, ValueError) as e:
            return False, str(e)
        if not self._value or not os.path.exists(self._value):
            return False, "The file does not exist"
        return super().should_run()

    def get_value_to_pivot_to(self) -> Any:
        file_content = open(self._value, "rb").read()
        os.unlink(self._value)
        return file_content
