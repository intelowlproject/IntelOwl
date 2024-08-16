import requests

from api_app.analyzers_manager import classes
from tests.mock_utils import MockUpResponse, if_mock_connections, patch


class MalprobSearch(classes.ObservableAnalyzer):
    url: str = "https://malprob.io/api"

    def update(self):
        pass

    def run(self):
        response = requests.get(
            f"{self.url}/search/{self.observable_name}",
            timeout=10,
        )
        response.raise_for_status()
        return response.json()

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.get",
                    return_value=MockUpResponse(
                        {
                            "report": {
                                "md5": "8a05a189e58ccd7275f7ffdf88c2c191",
                                "mime": "application/java-archive",
                                "name": "sample.apk",
                                "sha1": "a7a70f2f482e6b26eedcf1781b277718078c743a",
                                "size": 3425,
                                "test": 0,
                                "trid": """Android Package (63.7%) |
                                    Java Archive (26.4%) |
                                    ZIP compressed archive (7.8%) |
                                    PrintFox/Pagefox bitmap (1.9%)""",
                                "type": "ARCHIVE",
                                "label": "benign",
                                "magic": "application/java-archive",
                                "score": 0.0003923133846427324,
                                "nested": [
                                    {
                                        "name": "MANIFEST.MF",
                                        "size": 331,
                                        "type": "text/plain",
                                        "score": 0.0003923133846427324,
                                        "sha256": """b093f736dac9f016788f59d6218eb
                                        2c9015e30e01ec88dc031863ff83e998e33""",
                                        "complete": True,
                                        "supported": True,
                                    },
                                    {
                                        "name": "CERT.SF",
                                        "size": 384,
                                        "type": "text/plain",
                                        "score": 6.292509868171916e-06,
                                        "sha256": """db5b14f8ccb0276e6db502e2b3ad1e
                                        75728a2d65c1798fcbe1ed8e153b0b17a6""",
                                        "complete": True,
                                        "supported": True,
                                    },
                                    {
                                        "name": "a.png",
                                        "size": 87,
                                        "type": "image/png",
                                        "score": 0.0,
                                        "sha256": """cc30bfc9a985956c833a135389743e96
                                        835fdddae75aab5f06f3cb8d10f1af9f""",
                                        "complete": True,
                                        "supported": True,
                                    },
                                    {
                                        "name": "CERT.RSA",
                                        "size": 481,
                                        "type": "application/octet-stream",
                                        "score": "NaN",
                                        "sha256": """3b3b283f338421ae31532a508bbc6aa8c
                                        1da54fc75357cfa9ac97cd4e46040a7""",
                                        "complete": True,
                                        "supported": False,
                                    },
                                    {
                                        "name": "classes.dex",
                                        "size": 920,
                                        "type": "application/octet-stream",
                                        "score": "NaN",
                                        "sha256": """fab857801d10f45887ad376263de6bc1c
                                        9e1893060d63cb5ad4eefb72f354112""",
                                        "complete": True,
                                        "supported": False,
                                    },
                                    {
                                        "name": "resources.arsc",
                                        "size": 560,
                                        "type": "application/octet-stream",
                                        "score": "NaN",
                                        "sha256": """d118e4e8b4921dbcaa5874012fb8426a08
                                        a195461285dee7c42b1bd7c6028802""",
                                        "complete": True,
                                        "supported": False,
                                    },
                                    {
                                        "name": "AndroidManifest.xml",
                                        "size": 1248,
                                        "type": "application/octet-stream",
                                        "score": "NaN",
                                        "sha256": """a718ac6589ff638ba8d799824ecdf0a858
                                        77f9e0381e6b573bf552875dd04ce9""",
                                        "complete": True,
                                        "supported": False,
                                    },
                                ],
                                "sha256": """ac24043d48dadc390877a6151515565b
                                1fdc1dab028ee2d95d80bd80085d9376""",
                                "category": "ARCHIVE",
                                "complete": True,
                                "encoding": None,
                                "extracted": True,
                                "predicted": True,
                                "scan_time": 219511,
                                "supported": True,
                                "insert_date": 1717233771,
                                "parent_hash": [None],
                            },
                        },
                        200,
                    ),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
