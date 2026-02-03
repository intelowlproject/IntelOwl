# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

"""Quad9 DNS resolutions"""

import logging

from api_app.analyzers_manager import classes

from ..dns_responses import dns_resolver_response
from ..quad9_base import Quad9Base

logger = logging.getLogger(__name__)


class Quad9DNSResolver(Quad9Base, classes.ObservableAnalyzer):
    """Resolve a DNS query with Quad9"""

    @classmethod
    def update(cls) -> bool:
        pass

    def run(self):
        observable = self.convert_to_domain(self.observable_name, self.observable_classification)
        resolutions = self.quad9_dns_query(observable)
        return dns_resolver_response(observable, resolutions)
