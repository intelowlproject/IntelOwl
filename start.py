import subprocess
import argparse

INTELOWL_TAG_VERSION = "v1.9.1"

docker_analyzers = ["thug", "apk_analyzers", "box_js", "static_analyzers"]

path_mapping = {
    "default": "docker/default.yml",
    "test": "docker/test.override.yml",
    "ci": "docker/ci.override.yml",
    "traefik": "docker/traefik.override.yml",
    "multi_queue": "docker/multi-queue.override.yml",
    "apk_analyzers": "integrations/apk_analyzers/apk.yml",
    "box_js": "integrations/box-js/boxjs.yml",
    "static_analyzers": "integrations/static_analyzers/static_analyzers.yml",
    "thug": "integrations/thug/thug.yml",
    "apk_analyzers.test": "integrations/apk_analyzers/apk.test.yml",
    "box_js.test": "integrations/box-js/boxjs.test.yml",
    "static_analyzers.test": "integrations/static_analyzers/static_analyzers.test.yml",
    "thug.test": "integrations/thug/thug.test.yml",
}
path_mapping["all_analyzers"] = [path_mapping[key] for key in docker_analyzers]
path_mapping["all_analyzers.test"] = [
    path_mapping[key + ".test"] for key in docker_analyzers
]


def start():
    parser = argparse.ArgumentParser()
    # mandatory arguments
    parser.add_argument("mode", type=str, choices=["prod", "test", "ci"])
    parser.add_argument(
        "docker_command",
        type=str,
        choices=["build", "up", "start", "restart", "down", "kill", "logs", "ps"],
    )

    # integrations
    parser.add_argument(
        "--all_analyzers",
        required=False,
        action="store_true",
        help="Uses every integration",
    )
    for integration in docker_analyzers:
        parser.add_argument(
            "--" + integration,
            required=False,
            action="store_true",
            help="Uses the integration/" + integration + ".override.yml compose file",
        )

    # possible upgrades
    parser.add_argument(
        "--multi_queue",
        required=False,
        action="store_true",
        help="Uses the multiqueue.override.yml compose file",
    )
    parser.add_argument(
        "--traefik",
        required=False,
        action="store_true",
        help="Uses the traefik.override.yml compose file",
    )
    args, unknown = parser.parse_known_args()
    # logic
    test_appendix = ""
    if args.mode == "test":
        test_appendix = ".test"
    docker_flags = [
        args.__dict__[docker_analyzer] for docker_analyzer in docker_analyzers
    ]
    if args.all_analyzers and any(docker_flags):
        parser.error(
            "It is not possible to select both  "
            "`all_analyzers` and another docker container"
        )
        return
    command = "docker-compose"
    command += " -f " + path_mapping["default"]
    if args.mode in ["ci", "test"]:
        command += " -f " + path_mapping[args.mode]
    for key in ["traefik", "multi_queue"]:
        if args.__dict__[key]:
            command += " -f " + path_mapping[key]
    for key in docker_analyzers:
        if args.__dict__[key]:
            command += " -f " + path_mapping[key + test_appendix]
    if args.all_analyzers:
        command += "".join(
            [
                " -f " + analyzer
                for analyzer in path_mapping["all_analyzers" + test_appendix]
            ]
        )
    command += " -p intel_owl"
    command += " " + args.docker_command
    try:
        subprocess.run(command.split(" ") + unknown, check=True)
    except KeyboardInterrupt:
        subprocess.run(["docker-compose", "down"], check=True)


if __name__ == "__main__":
    start()
