from typing import Any

from api_app.pivots_manager.classes import Pivot


class Compare(Pivot):
    field_to_compare: str

    def _get_value(self, field: str) -> Any:
        report = self.related_reports.first()
        if not report:
            raise RuntimeError("No report found")
        content = report.report

        for key in field.split("."):
            try:
                content = content[key]
            except TypeError:
                if isinstance(content, list):
                    content = content[int(key)]
                else:
                    raise RuntimeError(f"Not found {field}")

        if isinstance(content, (int, dict)):
            raise ValueError(f"You can't use a {type(content)} as pivot")
        return content

    def should_run(self) -> bool:
        if len(list(self.related_reports)) != 1:
            self.report.errors.append(
                f"Unable to run pivot {self._config.name}"
                " because attached to more than one configuration"
            )
            return False
        try:
            self._value = self._get_value(self.field_to_compare)
        except (RuntimeError, ValueError):
            return False
        return True and super().should_run()

    def get_value_to_pivot_to(self) -> Any:
        return self._value
