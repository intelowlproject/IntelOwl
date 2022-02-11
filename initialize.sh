#!/bin/bash

set -e

MINIMUM_DOCKER_VERSION=1.13.0
MINIMUM_DOCKER_COMPOSE_VERSION=1.23.2
MINIMUM_PYTHON_VERSION=3.6

# Function to compare 2 semver version
semantic_version_comp () {
    if [[ $1 == $2 ]]
    then
        echo "equalTo"
        return
    fi
    local IFS=.
    local i ver1=($1) ver2=($2)
    # fill empty fields in ver1 with zeros
    for ((i=${#ver1[@]}; i<${#ver2[@]}; i++))
    do
        ver1[i]=0
    done
    for ((i=0; i<${#ver1[@]}; i++))
    do
        if [[ -z ${ver2[i]} ]]
        then
            # fill empty fields in ver2 with zeros
            ver2[i]=0
        fi
        if ((10#${ver1[i]} > 10#${ver2[i]}))
        then
            echo "greaterThan"
            return
        fi
        if ((10#${ver1[i]} < 10#${ver2[i]}))
        then
            echo "lessThan"
            return
        fi
    done
    echo "equalTo"
    return
}

echo "This script will check (and possibly guide you through) the installation of dependencies for IntelOwl!"
# Check if docker is installed
if ! [ -x "$(command -v docker)" ]; then
  echo 'Error: docker is not installed.' >&2
  # Ask if user wants to install docker
  read -p "Do you want to install docker? [y/n] " -n 1 -r
  echo
  if [[ $REPLY =~ ^[Yy]$ ]]; then
    # Install docker
    curl -fsSL https://get.docker.com -o get-docker.sh
    sh get-docker.sh
    # Check if docker is installed
    if ! [ -x "$(command -v docker)" ]; then
      echo 'Error: Could not install docker.' >&2
      exit 1
    fi
  else
    exit 1
  fi
else
  docker_version=$(docker version --format '{{.Server.Version}}')

  if [[ $(semantic_version_comp "$docker_version" "$MINIMUM_DOCKER_VERSION") == "lessThan" ]]; then
    echo "Error: Docker version is too old. Please upgrade to at least $MINIMUM_DOCKER_VERSION." >&2
    exit 1
  else
    echo "Docker version $docker_version detected"
  fi
fi

# Check if docker-compose is installed
if ! [ -x "$(command -v docker-compose)" ]; then
  echo 'Error: docker-compose is not installed.' >&2
  # Ask if user wants to install docker-compose
  read -p "Do you want to install docker-compose? [y/n] " -n 1 -r
  echo
  if [[ $REPLY =~ ^[Yy]$ ]]; then
    # Install docker-compose
    sudo curl -L "https://github.com/docker/compose/releases/download/1.29.2/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    sudo chmod +x /usr/local/bin/docker-compose
    sudo ln -s /usr/local/bin/docker-compose /usr/bin/docker-compose
    # Check if docker-compose is installed
    if ! [ -x "$(command -v docker-compose)" ]; then
      echo 'Error: Could not install docker-compose.' >&2
      exit 1
    fi
  else
    exit 1
  fi
else
  IFS=',' read -ra temp <<< "$(docker-compose --version)"
  docker_compose_version=$(echo "${temp[0]}"| awk '{print $NF}')

  if [[ $(semantic_version_comp "$docker_compose_version" "$MINIMUM_DOCKER_COMPOSE_VERSION") == "lessThan" ]]; then
    echo "Error: Docker-compose version is too old. Please upgrade to at least $MINIMUM_DOCKER_COMPOSE_VERSION." >&2
    exit 1
  else
    echo "Docker-compose version $docker_compose_version detected"
  fi
fi

# Check if python is installed
if ! [ -x "$(command -v python3)" ]; then
  echo 'Error: python3 is not installed.' >&2
  exit 1
else
  python_version=$(python3 --version| awk '{print $NF}')
  if [[ $(semantic_version_comp "$python_version" "$MINIMUM_PYTHON_VERSION") == "lessThan" ]]; then
    echo "Error: Python3 version is too old. Please upgrade to at least $MINIMUM_PYTHON_VERSION." >&2
    exit 1
  else
    echo "Python3 version $python_version detected"
  fi
fi

# Check if pip is installed
if ! [ -x "$(command -v pip3)" ]; then
  echo 'Error: pip3 is not installed.' >&2
  exit 1
else
  echo "pip3 is installed"
fi

echo "Installing python dependencies using pip..."
pip3 install -r requirements/pre-requirements.txt

echo "Looks like you're ready to go!"
echo "Now you can start IntelOwl by running the start.py file (eg: \`python3 start.py prod up\` for production environment)"
