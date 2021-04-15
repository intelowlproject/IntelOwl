import base64

from api_app.script_analyzers.classes import ObservableAnalyzer, DockerBasedAnalyzer
from api_app.exceptions import AnalyzerRunException


class Rendertron(ObservableAnalyzer, DockerBasedAnalyzer):
    name: str = "Rendertron"
    url: str = "http://rendertron:4006/screenshot/"

    def run(self):
        self.url = self.url + self.observable_name
        resp = self._docker_get()
        try:
            b64_img = base64.b64encode(resp.content).decode("utf-8")
            return {"screenshot": b64_img}
        except Exception as err:
            raise AnalyzerRunException(f"Failed to convert to base64 string {err}")
