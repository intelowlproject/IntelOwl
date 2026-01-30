from typing import Any, Optional, Tuple

from django.core.files import File

from api_app.pivots_manager.classes import Pivot
from api_app.pivots_manager.models import PivotConfig


class SelfAnalyzable(Pivot):
    def should_run(self) -> Tuple[bool, Optional[str]]:
        self._config: PivotConfig
        # if the pivot is executed, we should check to not have an infinite loop.
        # meaning that the playbook that we will run does not have
        # all the analyzers that are required to run the pivot again
        to_run, motivation = super().should_run()
        if to_run:
            related_config_class = self.related_configs.model
            related_configs_pk = set(self.related_configs.values_list("pk", flat=True))
            # the configs that the playbook execute that could match
            playbook_configs = set(
                related_config_class.objects.filter(
                    playbooks__in=self._config.playbooks_choice.all().values_list("pk", flat=True)
                ).values_list("pk", flat=True)
            )
            if related_configs_pk.issubset(playbook_configs):
                return False, f"Found possible infinite loop in {self._config.name}."
        return to_run, motivation

    def get_value_to_pivot_to(self) -> Any:
        if self._job.is_sample:
            return File(self._job.analyzable.file, name=self._job.analyzable.name)
        return self._job.analyzable.name
