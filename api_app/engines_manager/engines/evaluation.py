from functools import cmp_to_key

from django.db.models import Avg

from api_app.data_model_manager.enums import DataModelEvaluations
from api_app.data_model_manager.models import BaseDataModel
from api_app.engines_manager.classes import EngineModule

evaluations_order = {
    DataModelEvaluations.TRUSTED.value: 3,
    DataModelEvaluations.MALICIOUS.value: 2,
}


def comparison(item1: BaseDataModel, item2: BaseDataModel):
    if item1.reliability == item2.reliability:
        return evaluations_order[item1.evaluation] - evaluations_order[item2.evaluation]
    return item1.reliability - item2.reliability


class EvaluationEngineModule(EngineModule):
    def run(self):
        analyzer_evaluations = self.job.get_analyzers_data_models().order_by("-reliability")
        user_evaluations = self.job.get_user_events_data_model()
        if not analyzer_evaluations.exists() and not user_evaluations.exists():
            return {
                "evaluation": None,
                "reliability": 0,
            }
        # if we have a user evaluation, the one with most reliability wins.
        # if more then 1 has same reliability, we follow the evaluations_order
        if user_evaluations.exists():
            result = sorted(user_evaluations, key=cmp_to_key(comparison), reverse=True)[0]
            return {
                "evaluation": result.evaluation,
                "reliability": result.reliability,
            }

        else:
            result = (
                analyzer_evaluations.values("evaluation")
                .annotate(reliability=Avg("reliability"))
                .order_by("-reliability")
                .first()
            )
            return result
