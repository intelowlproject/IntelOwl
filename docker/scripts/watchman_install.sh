#!/bin/bash  

echo "WATCHMAN value is "
echo "$WATCHMAN"

# This script can be disabled during development using WATCHMAN=false env variable
if [ "$WATCHMAN" = "false" ]; then echo "Skipping WATCHMAN installation because we are not in test mode"; exit 0;  fi

pip3 install --compile -r requirements/django-server-requirements.txt

# install Watchman to enhance performance on the Django development Server
# https://docs.djangoproject.com/en/3.2/ref/django-admin/#runserver
cd /tmp || exit  
wget https://github.com/facebook/watchman/archive/refs/tags/v2024.05.13.00.zip
unzip v2024.05.13.00.zip*
cd watchman-2024.05.13.00 || exit
mkdir -p /usr/local/{bin,lib} /usr/local/var/run/watchman
cp bin/* /usr/local/bin
cp lib/* /usr/local/lib
chmod 755 /usr/local/bin/watchman
chmod 2777 /usr/local/var/run/watchman
wget http://archive.ubuntu.com/ubuntu/pool/main/o/openssl/libssl1.1_1.1.0g-2ubuntu4_amd64.deb
dpkg -i libssl1.1_1.1.0g-2ubuntu4_amd64.deb
rm -rf v2024.05.13.00.zip*
