# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import argparse
import os
import re
import subprocess

try:
    from dotenv import load_dotenv
    from git import Repo
except ImportError:
    print(
        "you must install the Python requirements."
        " See: https://intelowl.readthedocs.io/en/latest/Installation.html"
    )
    exit(2)


load_dotenv("docker/.env")
CURRENT_VERSION = os.getenv("REACT_APP_INTELOWL_VERSION", "").replace("v", "")

DOCKER_ANALYZERS = [
    "tor_analyzers",
    "rendertron",
    "malware_tools_analyzers",
    "cyberchef",
    "pcap_analyzers",
]

PATH_MAPPING = {
    "default": "docker/default.yml",
    "test": "docker/test.override.yml",
    "ci": "docker/ci.override.yml",
    "custom": "docker/custom.override.yml",
    "traefik": "docker/traefik.override.yml",
    "multi_queue": "docker/multi-queue.override.yml",
    "test_multi_queue": "docker/test.multi-queue.override.yml",
    "flower": "docker/flower.override.yml",
    "test_flower": "docker/test.flower.override.yml",
    "elastic": "docker/elasticsearch.override.yml",
    "https": "docker/https.override.yml",
}
# to fix the box-js folder name
PATH_MAPPING.update(
    {name: f"integrations/{name}/compose.yml" for name in DOCKER_ANALYZERS}
)
PATH_MAPPING.update(
    {
        name + ".test": f"integrations/{name}/compose-tests.yml"
        for name in DOCKER_ANALYZERS
    }
)
PATH_MAPPING["all_analyzers"] = [PATH_MAPPING[key] for key in DOCKER_ANALYZERS]
PATH_MAPPING["all_analyzers.test"] = [
    PATH_MAPPING[key + ".test"] for key in DOCKER_ANALYZERS
]


def version_regex(arg_value, pat=re.compile(r"^[3-4]\.[0-9]{1,2}.[0-9]{1,2}$")):
    if not pat.match(arg_value):
        raise argparse.ArgumentTypeError
    return arg_value


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
        "--project_name", required=False, help="project name", default="intel_owl"
    )
    parser.add_argument(
        "--version",
        required=False,
        type=version_regex,
        default=CURRENT_VERSION,
        help="choose the version you would like to install (>=3.0.0)."
        " Works only in 'prod' mode",
    )
    # integrations
    parser.add_argument(
        "--all_analyzers",
        required=False,
        action="store_true",
        help="Uses every integration",
    )
    for integration in DOCKER_ANALYZERS:
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
        "--debug-build",
        required=False,
        action="store_true",
        help="see more verbose output from the build, for debug purposes",
    )
    parser.add_argument(
        "--elastic",
        required=False,
        action="store_true",
        help="This spins up Elasticsearch"
        "and Kibana on your machine (might need >=16GB of RAM)",
    )
    parser.add_argument(
        "--https",
        required=False,
        action="store_true",
        help="This leverage the https.override.yml file that can be used "
        "to host IntelOwl with HTTPS and your own certificate",
    )

    args, unknown = parser.parse_known_args()
    # logic
    test_appendix = ""
    is_test = False
    if args.mode in ["test", "ci"]:
        is_test = True
        test_appendix = ".test"
    # load relevant .env file
    load_dotenv("docker/.env.start" + test_appendix)
    docker_flags = [
        args.__dict__[docker_analyzer] for docker_analyzer in DOCKER_ANALYZERS
    ]
    if args.all_analyzers and any(docker_flags):
        parser.error(
            "It is not possible to select both  "
            "`all_analyzers` and another docker container"
        )
        return
    # default file
    compose_files = [PATH_MAPPING["default"]]
    # mode
    if is_test:
        compose_files.append(PATH_MAPPING[args.mode])
    if args.__dict__["elastic"]:
        compose_files.append(PATH_MAPPING["elastic"])
    if args.__dict__["https"]:
        compose_files.append(PATH_MAPPING["https"])
    # upgrades
    for key in ["traefik", "multi_queue", "custom", "flower"]:
        if args.__dict__[key]:
            compose_files.append(PATH_MAPPING[key])
    # additional compose files for tests
    if args.mode == "test":
        for key in ["multi_queue", "flower"]:
            if args.__dict__[key]:
                compose_files.append(PATH_MAPPING["test_" + key])
    # additional integrations
    for key in DOCKER_ANALYZERS:
        if args.__dict__[key]:
            compose_files.append(PATH_MAPPING[key])
            if is_test:
                compose_files.append(PATH_MAPPING[key + test_appendix])
    if args.all_analyzers:
        compose_files.extend(list(PATH_MAPPING["all_analyzers"]))
        if is_test:
            compose_files.extend(list(PATH_MAPPING[f"all_analyzers{test_appendix}"]))

    if args.mode == "prod" and args.version != CURRENT_VERSION:
        print(
            f"Requested version {args.version} is different "
            f"from current version {CURRENT_VERSION}"
        )
        current_dir = os.getcwd()
        repo = Repo(current_dir)
        git = repo.git
        git.config("--global", "--add", "safe.directory", current_dir)
        git.checkout(f"tags/v{args.version}")

    # construct final command
    base_command = [
        "docker-compose",
        "-p",
        args.project_name,
        "--project-directory",
        "docker",
    ]
<<<<<<< HEAD
    # for docker-compose v2
    try:subprocess.run(base_command[0],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True)
    except OSError:base_command= ["docker","compose"] + base_command[1:]
        
=======
    

>>>>>>> parent of 6c5d589 (Update start.py)
    for compose_file in compose_files:
        base_command.append("-f")
        base_command.append(compose_file)
    # we use try/catch to mimick docker-compose's behaviour of handling CTRL+C event
    try:
         try:
                command = base_command + [args.docker_command] + unknown
                env = os.environ.copy()
                env["DOCKER_BUILDKIT"] = "1"
                if args.debug_build:
                        env["BUILDKIT_PROGRESS"] = "plain"
                subprocess.run(command, env=env, check=True)
        #for docker compose v2
        except OSError :
                command = ["docker","compose"] + base_command[1:] + [args.docker_command] + unknown
                env = os.environ.copy()
                env["DOCKER_BUILDKIT"] = "1"
                if args.debug_build:
                        env["BUILDKIT_PROGRESS"] = "plain"
                subprocess.run(command, env=env, check=True)


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
