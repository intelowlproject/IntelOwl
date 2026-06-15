# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from langchain_core.tools import tool

from api_app.chatbot_manager.serializers.data_model import DataModelResultSerializer
from api_app.models import Job


def make_get_data_model_tool(user):
    # Built per-request and closed over `user`: scoped with visible_for_user (owner +
    # same-org AMBER/RED + globally-visible CLEAR/GREEN), matching the other job tools and
    # the UI (multi-tenancy enforced here). LangChain feeds a tool's return value back as
    # the tool-call observation, so it must be a string: we return a JSON-serialized envelope.
    @tool("get_data_model")
    def get_data_model(job_id: int) -> str:
        """Get the aggregated data model of an IntelOwl job by its numeric ID.

        The data model is IntelOwl's normalized, analyzer-agnostic view of a job's
        observable (evaluation, reliability, tags, kill-chain phase, plus type-specific
        fields for domains/IPs/files). It is empty until the analysis pipeline has built
        it, so an empty object is a valid result.

        Args:
            job_id: The numeric ID of the job.

        Returns:
            JSON string with shape {"errors": [...], "data_model": {...}}.
        """
        try:
            job = Job.objects.visible_for_user(user).get(pk=job_id)
        except Job.DoesNotExist:
            return DataModelResultSerializer(
                {"errors": [f"Job with ID {job_id} not found or not accessible."], "data_model": {}}
            ).to_json()

        # Mirror the public JobSerializer.get_data_model: the model serializes itself
        # (polymorphic across Domain/IP/File); `data_model` is a nullable GenericForeignKey.
        data_model = job.data_model.serialize() if job.data_model else {}
        return DataModelResultSerializer({"errors": [], "data_model": data_model}).to_json()

    return get_data_model
