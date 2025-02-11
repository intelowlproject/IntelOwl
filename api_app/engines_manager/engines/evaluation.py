from api_app.data_model_manager.enums import DataModelEvaluations
from api_app.engines_manager.classes import EngineModule


class EvaluationEngineModule(EngineModule):
    evaluations_order = [
        DataModelEvaluations.TRUSTED.value,
        DataModelEvaluations.MALICIOUS.value,
        DataModelEvaluations.SUSPICIOUS.value,
        DataModelEvaluations.CLEAN.value,
    ]

    def run(self):
        evaluations = self.job.get_analyzers_data_models().values_list(
            "evaluation", flat=True
        )

        evaluation = DataModelEvaluations.CLEAN.value
        for key in self.evaluations_order:
            if key in evaluations:
                evaluation = key
                break
        return {
            "evaluation": evaluation,
        }
