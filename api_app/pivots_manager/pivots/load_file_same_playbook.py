from api_app.pivots_manager.models import PivotConfig
from api_app.pivots_manager.pivots.load_file import LoadFile


class LoadFileSamePlaybook(LoadFile):
    field_to_compare: str

    @classmethod
    def update(cls) -> bool:
        pass

    def get_playbook_to_execute(self):
        self._config: PivotConfig
        # use the same playbook of the parent when resubmit a file
        return self._job.get_root().playbook_to_execute
