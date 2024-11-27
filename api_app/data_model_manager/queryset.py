from typing import Dict, List

from django.db.models import QuerySet


class BaseDataModelQuerySet(QuerySet):
    def serialize(self) -> List[Dict]:
        return self.model.get_serializer()(self, many=True, read_only=True).data
