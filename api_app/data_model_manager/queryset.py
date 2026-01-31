import typing
from typing import Dict, List

from django.db.models import QuerySet

if typing.TYPE_CHECKING:
    from api_app.data_model_manager.models import BaseDataModel


class BaseDataModelQuerySet(QuerySet):
    def merge(self, append: bool = True) -> "BaseDataModel":
        """
        Base method of merge of multiple data models.
        :return: BaseDataModel
        """
        result_obj: BaseDataModel = self.model.objects.create()
        for obj in self:
            result_obj.merge(obj, append=append)
        return result_obj

    def serialize(self) -> List[Dict]:
        try:
            serializer_class = self.model.get_serializer()
        except NotImplementedError:
            return []
        return serializer_class(self, many=True, read_only=True).data
