from typing import Any, Optional, Tuple

from api_app.pivots_manager.classes import Pivot


class Compare(Pivot):
    field_to_compare: str

    @classmethod
    def update(cls) -> bool:
        pass

    def _get_value(self, field: str) -> Any:
        report = self.related_reports.filter(
            status=self.report_model.Status.SUCCESS.value
        ).first()
        if not report:
            raise RuntimeError("No report found")
        content = report.report

        for key in field.split("."):
            try:
                content = content[key]
            except TypeError:
                if isinstance(content, list) and len(content) > 0:
                    content = content[int(key)]
                else:
                    raise RuntimeError(f"Not found {field}")

        if isinstance(content, (int, dict)):
            raise ValueError(f"You can't use a {type(content)} as pivot")
        return content

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
        return super().should_run()

    def get_value_to_pivot_to(self) -> Any:
        return self._value
