from typing import TYPE_CHECKING, Type

from django.db.models import Exists, OuterRef

from api_app.queryset import AbstractReportQuerySet, PythonConfigQuerySet
from certego_saas.apps.user.models import User

if TYPE_CHECKING:
    from api_app.ingestors_manager.serializers import IngestorReportBISerializer


class IngestorReportQuerySet(AbstractReportQuerySet):
    @classmethod
    def _get_bi_serializer_class(cls) -> Type["IngestorReportBISerializer"]:
        from api_app.ingestors_manager.serializers import IngestorReportBISerializer

        return IngestorReportBISerializer


class IngestorQuerySet(PythonConfigQuerySet):
    """
    Custom queryset for Ingestor model, providing methods for annotating configurations specific to ingestors.

    Methods:
    - annotate_runnable: Annotates ingestors indicating if they are runnable.
    """

    def annotate_runnable(self, user: User = None) -> "PythonConfigQuerySet":
        """
        Annotates ingestors indicating if they are runnable.

        Args:
            user (User, optional): The user to check. Defaults to None.

        Returns:
            PythonConfigQuerySet: The annotated queryset.
        """
        # the plugin is runnable IF
        # - it is not disabled
        qs = self.filter(
            pk=OuterRef("pk"),
        ).exclude(disabled=True)

        return self.annotate(runnable=Exists(qs))
