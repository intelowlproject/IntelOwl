# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import argparse
import subprocess

from dotenv import load_dotenv

docker_analyzers = [
    "thug",
    "apk_analyzers",
    "tor_analyzers",
    "box_js",
    "rendertron",
    "static_analyzers",
    "qiling",
]

path_mapping = {
    "default": "docker/default.yml",
    "test": "docker/test.override.yml",
    "ci": "docker/ci.override.yml",
    "django_server": "docker/django-server.override.yml",
    "custom": "docker/custom.override.yml",
    "traefik": "docker/traefik.override.yml",
    "multi_queue": "docker/multi-queue.override.yml",
    "test_multi_queue": "docker/test.multi-queue.override.yml",
    "flower": "docker/flower.override.yml",
    "test_flower": "docker/test.flower.override.yml",
    "elastic": "docker/elasticsearch.override.yml",
}
# to fix the box-js folder name
path_mapping.update(
    {
        name: f"integrations/{name.replace('box_js', 'box-js')}/compose.yml"
        for name in docker_analyzers
    }
)
path_mapping.update(
    {
        name
        + ".test": f"integrations/{name.replace('box_js', 'box-js')}/compose-tests.yml"
        for name in docker_analyzers
    }
)
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
        choices=[
            "build",
            "up",
            "start",
            "restart",
            "down",
            "stop",
            "kill",
            "logs",
            "ps",
        ],
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
            f"--{integration}",
            required=False,
            action="store_true",
            help=f"Uses the integrations/{integration}/compose.yml file",
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
    parser.add_argument(
        "--flower",
        required=False,
        action="store_true",
        help="Uses the flower.override.yml compose file",
    )
    parser.add_argument(
        "--custom",
        required=False,
        action="store_true",
        help="Uses custom.override.yml to leverage your customized configuration",
    )
    parser.add_argument(
        "--django-server",
        required=False,
        action="store_true",
        help="While using 'test' mode, this allows to use the default"
        " Django server instead of Uwsgi",
    )
    parser.add_argument(
        "--elastic",
        required=False,
        action="store_true",
        help="This spins up Elasticsearch"
        "and Kibana on your machine (might need >=16GB of RAM)",
    )

    args, unknown = parser.parse_known_args()
    # logic
    test_appendix = ""
    if args.mode == "test":
        test_appendix = ".test"
    # load relevant .env file
    load_dotenv("docker/.env.start" + test_appendix)
    docker_flags = [
        args.__dict__[docker_analyzer] for docker_analyzer in docker_analyzers
    ]
    if args.all_analyzers and any(docker_flags):
        parser.error(
            "It is not possible to select both  "
            "`all_analyzers` and another docker container"
        )
        return
    # default file
    compose_files = [path_mapping["default"]]
    # mode
    if args.mode == "ci":
        compose_files.append(path_mapping[args.mode])
    elif args.mode == "test":
        if args.__dict__["django_server"]:
            compose_files.append(path_mapping["django_server"])
        else:
            compose_files.append(path_mapping[args.mode])
    if args.__dict__["elastic"]:
        compose_files.append(path_mapping["elastic"])
    # upgrades
    for key in ["traefik", "multi_queue", "custom", "flower"]:
        if args.__dict__[key]:
            compose_files.append(path_mapping[key])
    # additional compose files for tests
    if args.mode == "test":
        for key in ["multi_queue", "flower"]:
            if args.__dict__[key]:
                compose_files.append(path_mapping["test_" + key])
    # additional integrations
    for key in docker_analyzers:
        if args.__dict__[key]:
            compose_files.append(path_mapping[key + test_appendix])
    if args.all_analyzers:
        compose_files.extend(list(path_mapping[f"all_analyzers{test_appendix}"]))

    # construct final command
    base_command = [
        "docker-compose",
        "-p",
        "intel_owl",
        "--project-directory",
        "docker",
    ]
    for compose_file in compose_files:
        base_command.append("-f")
        base_command.append(compose_file)
    # we use try/catch to mimick docker-compose's behaviour of handling CTRL+C event
    try:
        command = base_command + [args.docker_command] + unknown
        subprocess.run(command)
    except KeyboardInterrupt:
        print(
            "---- removing the containers, please wait... ",
            "(press Ctrl+C again to force) ----",
        )
        try:
            subprocess.run(base_command + ["down"])
        except KeyboardInterrupt:
            # just need to catch it
            pass


if __name__ == "__main__":
    start()
