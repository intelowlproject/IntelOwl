#!/bin/bash

# This script can be disabled during development using REPO_DOWNLOADER_ENABLED=true env variable
if [ "WATCHMAN" = "false" ]; then echo "Skipping WATCHMAN installation because we are not in test mode"; exit 0;  fi

pip3 install --compile -r requirements/django-server-requirements.txt

# install Watchman to enhance performance on the Django development Server
# https://docs.djangoproject.com/en/3.2/ref/django-admin/#runserver
cd /tmp
wget https://github.com/facebook/watchman/releases/download/v2022.03.21.00/watchman-v2022.03.21.00-linux.zip
unzip watchman-*-linux.zip
cd watchman-*-linux/
mkdir -p /usr/local/{bin,lib} /usr/local/var/run/watchman
cp bin/* /usr/local/bin
cp lib/* /usr/local/lib
chmod 755 /usr/local/bin/watchman
chmod 2777 /usr/local/var/run/watchman
rm -rf watchman-*-linux*