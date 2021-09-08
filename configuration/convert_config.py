# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import json


def main():
    file_path = "connector_config.json"
    with open(file_path, "r") as f:
        analyzer_configs = json.load(f)

    new_config = {}
    for name, config in analyzer_configs.items():
        new_config[name] = {
            **config,
            "config": {
                param: value
                for param, value in config["config"].items()
                if param in ["soft_time_limit", "queue"]
            },
            "params": {
                param: {
                    "value": value,
                    "type": type(value).__name__,
                    "description": "",
                }
                for param, value in config["config"].items()
                if param not in ["soft_time_limit", "queue"]
            },
        }

    with open("new_connector_config.json", "w") as f:
        json.dump(new_config, f, indent=2)


if __name__ == "__main__":
    main()
