import abc

from api_app.analyzers_manager.classes import BaseAnalyzerMixin


class CriminalIpBase(BaseAnalyzerMixin, metaclass=abc.ABCMeta):
    url = "https://api.criminalip.io"
    _api_key: str = None

    def update(self):
        pass

    def getHeaders(self):
        return {"x-api-key": self._api_key}
