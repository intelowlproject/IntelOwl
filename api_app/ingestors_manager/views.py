# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging

from api_app.ingestors_manager.serializers import IngestorConfigSerializer
from api_app.views import PythonConfigViewSet

logger = logging.getLogger(__name__)


class IngestorConfigViewSet(PythonConfigViewSet):
    serializer_class = IngestorConfigSerializer
