#!/usr/bin/env bash

set -e

MINIMUM_DOCKER_VERSION=19.03.0
MINIMUM_DOCKER_COMPOSE_VERSION=2.3.4

# Function to compare 2 semver version
semantic_version_comp () {
  if [[ "$1" == "$2" ]]; then 
      echo "equalTo"
      return
  fi

  # Remove "v" prefix if present
  ver1="${1//v/}"  # Used parameter substitution instead of sed (SC2001)
  ver2="${2//v/}"

  # Convert version numbers to arrays
  local IFS=.
  local i ver1=("${ver1[@]}") ver2=("${ver2[@]}") 

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

# check if env file exists and DJANGO_SECRET has been set using approved characters in django source code
check_django_secret () {
  # https://regex101.com/r/O778RQ/1
  if [ ! -e docker/env_file_app ] || ! ( tac docker/env_file_app | grep -qE "^DJANGO_SECRET=[a-z0-9\!\@\#\$\%\^\&\*\(\-\_\=\+\)]{50,}$" ); then
    echo "DJANGO_SECRET variable not found! Generating a new one."
    python3 -c 'import secrets; print("DJANGO_SECRET="+"".join(secrets.choice("abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*(-_=+)") for i in range(50)))' >> docker/env_file_app
  fi
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
    rm get-docker.sh
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

# construct environment files from templates
echo "Adding environment files"
cp -n docker/env_file_app_template docker/env_file_app
cp -n docker/env_file_postgres_template docker/env_file_postgres
cp -n docker/env_file_integrations_template docker/env_file_integrations
echo "Added environment files"

check_django_secret

echo "Adding Logrotate configuration to Systems logrotate"
cd ./docker/scripts
./install_logrotate.sh
echo "Added Logrotate configuration to Systems logrotate"
echo "Moving to root of the project"
cd -

echo "Looks like you're ready to go!"