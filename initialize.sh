#!/bin/bash

set -e

MINIMUM_DOCKER_VERSION=1.13.0
MINIMUM_DOCKER_COMPOSE_VERSION=1.23.2
MINIMUM_PYTHON_VERSION=3.6

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
echo "CARE! This script is delivered AS IS and could not work correctly in every possible environment. In the case you face any error, you should just follow the official documentation and do all the required operation manually."

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
    echo 'You chose to do not install Docker. Exiting'
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

if  [ "$(docker --help | grep -q 'compose')" == 0 ] && ! [ -x "$(command -v docker-compose)" ]; then
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
  if  docker --help | grep -q 'compose'; then
    docker_compose_version="$(docker compose version | cut -d 'v' -f3)"
  else
    IFS=',' read -ra temp <<< "$(docker-compose --version)"
    docker_compose_version=$(echo "${temp[0]}"| awk '{print $NF}')
  fi
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
#pip requires --user flag for gentoo
pip3 install --user -r requirements/pre-requirements.txt
echo "Python dependencies installed!"

echo "Adding Logrotate configuration to Systems logrotate"
cd ./docker/scripts
./install_logrotate.sh
echo "Added Logrotate configuration to Systems logrotate"
cd -

echo "Looks like you're ready to go!"
echo "Now you can start IntelOwl by running the start.py file (eg: \`python3 start.py prod up\` for production environment)"
