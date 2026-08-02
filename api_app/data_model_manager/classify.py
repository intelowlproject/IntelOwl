# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from api_app.data_model_manager.enums import DataModelEvaluations

# Presentation buckets — the single source of truth consumed by both the
# DataModel visualizer and (later) the chatbot, so every surface says the same
# word for the same (evaluation, reliability) pair.
BUCKET_TRUSTED = "trusted"
BUCKET_CLEAN = "clean"
BUCKET_MALICIOUS = "malicious"
BUCKET_SUSPICIOUS = "suspicious"
BUCKET_NO_EVALUATION = "no evaluation"

# Bucket boundaries (verbatim from the pre-existing visualizer logic this
# function replaced).
TRUSTED_RELIABILITY_FLOOR = 8
MALICIOUS_RELIABILITY_FLOOR = 6


def classify(evaluation: str | None, reliability: int) -> str:
    """Map a (evaluation, reliability) pair to one of the five presentation buckets.

    Single source of truth for the bucketing: the DataModel visualizer calls this
    (and the chatbot will), so the badge and the chat always agree.
    """
    if evaluation == DataModelEvaluations.TRUSTED.value:
        return BUCKET_TRUSTED if reliability >= TRUSTED_RELIABILITY_FLOOR else BUCKET_CLEAN
    if evaluation == DataModelEvaluations.MALICIOUS.value:
        return BUCKET_MALICIOUS if reliability >= MALICIOUS_RELIABILITY_FLOOR else BUCKET_SUSPICIOUS
    return BUCKET_NO_EVALUATION
