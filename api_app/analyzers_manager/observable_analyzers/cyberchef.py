# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import json

import requests
from django.conf import settings

from api_app.analyzers_manager.classes import DockerBasedAnalyzer, ObservableAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException


class CyberChef(ObservableAnalyzer, DockerBasedAnalyzer):
    name: str = "CyberChefServer"
    url: str = "http://cyberchef-server:3000/bake"
    config_filename: str = "cyberchef_recipes.json"

    def set_params(self, params):
        self.recipe_name = params.get("recipe_name", "")
        if self.recipe_name:
            try:
                try:
                    with open(
                        f"{settings.PROJECT_LOCATION}/configuration/"
                        f"{self.config_filename}",
                        "r",
                    ) as recipes:
                        parsed_recipes = json.load(recipes)
                        self.recipe = parsed_recipes[self.recipe_name]
                except FileNotFoundError:
                    raise AnalyzerRunException(
                        f"Could not open configuration file {self.config_filename}"
                    )
                except json.JSONDecodeError:
                    raise AnalyzerRunException(
                        f"Could not parse the configuration file. Please check "
                        f"{self.config_filename}"
                    )

            except KeyError:
                raise AnalyzerRunException(
                    f"Unknown predefined recipe: {self.recipe_name}"
                )
        else:
            self.recipe = params.get("recipe_code", [])
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
