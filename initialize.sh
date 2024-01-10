#!/usr/bin/env bash

set -e

MINIMUM_DOCKER_VERSION=19.03.0
MINIMUM_DOCKER_COMPOSE_VERSION=2.3.4
#MINIMUM_PYTHON_VERSION=3.6

# Function to compare 2 semver version
semantic_version_comp () {
    if [[ $1 == $2 ]]; then
        echo "equalTo"
        return
    fi

    # Remove "v" prefix if present
    ver1=$(echo $1 | sed 's/^v//')
    ver2=$(echo $2 | sed 's/^v//')

    # Convert version numbers to arrays
    local IFS=.
    local i ver1=($ver1) ver2=($ver2)

    # Fill empty fields in ver1 with zeros
    for ((i=${#ver1[@]}; i<${#ver2[@]}; i++)); do
        ver1[i]=0
    done

    # Compare version numbers
    for ((i=0; i<${#ver1[@]}; i++)); do
        if [[ -z ${ver2[i]} ]]; then
            # Fill empty fields in ver2 with zeros
            ver2[i]=0
        fi
        if ((10#${ver1[i]} > 10#${ver2[i]})); then
            echo "greaterThan"
            return
        fi
        if ((10#${ver1[i]} < 10#${ver2[i]})); then
            echo "lessThan"
            return
        fi
    done

    # If we reach this point, the versions are equal
    echo "equalTo"
}

echo "This script will check (and possibly guide you through) the installation of dependencies for IntelOwl!"
echo "CARE! This script is delivered AS IS and could not work correctly in every possible environment. It has been tested on Ubuntu 22.04 LTS. In the case you face any error, you should just follow the official documentation and do all the required operation manually."

# Check if docker is installed
if ! [ -x "$(command -v docker)" ]; then
  echo 'Error: docker is not installed.' >&2
  # Ask if user wants to install docker
  read -p "Do you want to install docker? [y/n] " -n 1 -r
  echo
  if [[ $REPLY =~ ^[Yy]$ ]]; then
    # Install docker
    if ! curl --version > /dev/null 2>&1; then
      echo "curl is required to install dependencies." >&2
      exit 1
    fi
    curl -fsSL https://get.docker.com -o get-docker.sh
    sudo sh get-docker.sh
    # Check if docker is installed
    if ! [ -x "$(command -v docker)" ]; then
      echo 'Error: Could not install docker.' >&2
      exit 1
    fi
  else
    echo 'You chose to do not install Docker. Exiting'
    exit 1
  fi
else
  docker_version=$(sudo docker version --format '{{.Server.Version}}')

  if [[ $(semantic_version_comp "$docker_version" "$MINIMUM_DOCKER_VERSION") == "lessThan" ]]; then
    echo "Error: Docker version is too old. Please upgrade to at least $MINIMUM_DOCKER_VERSION." >&2
    exit 1
  else
    echo "Docker version $docker_version detected"
  fi
fi

# docker compose V1 is no longer supported
if [ -x "$(command -v docker-compose)" ] && ! docker compose version; then
  echo "Error: Docker compose V1 is no longer supported. Please install at least v$MINIMUM_DOCKER_COMPOSE_VERSION of docker compose V2." >&2
  exit 1
fi

if ! docker compose version; then
  echo 'Error: docker compose is not installed.' >&2
  # Ask if user wants to install docker compose
  read -p "Do you want to install docker compose? [y/n] " -n 1 -r
  echo
  if [[ $REPLY =~ ^[Yy]$ ]]; then
    # Install docker compose
    sudo curl -SL "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/lib/docker/cli-plugins/docker-compose
    sudo chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
    # Check if docker compose is installed
    if ! docker compose version; then
      echo 'Error: Could not install docker compose.' >&2
      exit 1
    fi
  else
    echo 'You chose to do not install docker compose. Exiting' >&2
    exit 1
  fi
else
  # docker compose exists
  docker_compose_version="$(docker compose version | cut -d 'v' -f3)"
  if [[ $(semantic_version_comp "$docker_compose_version" "$MINIMUM_DOCKER_COMPOSE_VERSION") == "lessThan" ]]; then
    echo "Error: Docker compose version is too old. Please upgrade to at least $MINIMUM_DOCKER_COMPOSE_VERSION." >&2
    exit 1
  else
    echo "Docker compose version $docker_compose_version detected"
  fi
fi

# Check if python is installed
#if ! [ -x "$(command -v python3)" ]; then
#  echo 'Error: Python3 is not installed. Please install it.' >&2
#  exit 1
#else
#  python_version=$(python3 --version| awk '{print $NF}')
#  if [[ $(semantic_version_comp "$python_version" "$MINIMUM_PYTHON_VERSION") == "lessThan" ]]; then
#    echo "Error: Python3 version is too old. Please upgrade to at least $MINIMUM_PYTHON_VERSION." >&2
#    exit 1
#  else
#    echo "Python3 version $python_version detected"
#  fi
#fi
#
#if [ -d "venv" ]; then
#  echo "Found virtual environment \`venv\`"
#else
#  echo "Creating virtual environment \`venv\`"
#
#  if ! dpkg -s python3-venv ; then
#    echo "Installing python3-venv from apt"
#    sudo apt install python3-venv -y
#  fi
#  python3 -m venv venv
#fi

echo "Adding Logrotate configuration to Systems logrotate"
cd ./docker/scripts
./install_logrotate.sh
echo "Added Logrotate configuration to Systems logrotate"
echo "Moving to root of the project"
cd -

echo "Looks like you're ready to go!"