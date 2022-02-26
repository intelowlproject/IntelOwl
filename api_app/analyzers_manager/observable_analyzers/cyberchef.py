# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import requests

from api_app.analyzers_manager.classes import DockerBasedAnalyzer, ObservableAnalyzer
from api_app.exceptions import AnalyzerRunException

PREDEFINED_RECIPES = {"to decimal": [{"op": "To Decimal", "args": ["Space", False]}]}


class CyberChef(ObservableAnalyzer, DockerBasedAnalyzer):
    name: str = "CyberChefServer"
    url: str = "http://cyberchef-server:3000/bake"

    def set_params(self, params):
        self.predefined_recipe_name = params.get("predefined_recipe_name", "")
        if self.predefined_recipe_name:
            try:
                self.recipe = PREDEFINED_RECIPES[self.predefined_recipe_name]
            except KeyError:
                raise AnalyzerRunException(
                    f"Unknown predefined recipe: {self.predefined_recipe_name}"
                )
        else:
            self.recipe = params.get("custom_recipe", [])
        self.output_type = params.get("output_type", "")

    def run(self):

        try:
            request_payload = {"input": self.observable_name, "recipe": self.recipe}
            if self.output_type:
                request_payload["outputType"] = self.output_type
            response = requests.post(self.url, json=request_payload)
            response.raise_for_status()
        except requests.RequestException as e:
            raise AnalyzerRunException(e)

        result = response.json()

        return result
