from api_app.core.views import AbstractConfigViewSet
from api_app.pivot_manager.serializers import PivotConfigSerializer


class PivotConfigViewSet(AbstractConfigViewSet):
    serializer_class = PivotConfigSerializer
