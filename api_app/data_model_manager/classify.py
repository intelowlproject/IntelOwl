# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from api_app.data_model_manager.enums import DataModelEvaluations, DataModelVerdictBuckets

# Bucket boundaries (verbatim from the pre-existing visualizer logic this
# function replaced).
TRUSTED_RELIABILITY_FLOOR = 8
MALICIOUS_RELIABILITY_FLOOR = 6


def classify(evaluation: str | None, reliability: int) -> str:
    """Map a (evaluation, reliability) pair to one of the five presentation buckets.

    Single source of truth for the bucketing: the DataModel visualizer calls this
    and so does the chatbot, so the badge and the chat always agree.
    """
    if evaluation == DataModelEvaluations.TRUSTED.value:
        return (
            DataModelVerdictBuckets.TRUSTED.value
            if reliability >= TRUSTED_RELIABILITY_FLOOR
            else DataModelVerdictBuckets.CLEAN.value
        )
    if evaluation == DataModelEvaluations.MALICIOUS.value:
        return (
            DataModelVerdictBuckets.MALICIOUS.value
            if reliability >= MALICIOUS_RELIABILITY_FLOOR
            else DataModelVerdictBuckets.SUSPICIOUS.value
        )
    return DataModelVerdictBuckets.NO_EVALUATION.value
