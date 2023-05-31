#!/bin/bash

# this is a simple script that downloads public yara repositories and make some changes on their configuration
# we have also added the download of other tools like quark-engine rules, dnstwist dictionaries and exiftool

# I suggest you to modify this script based on your needs.
# Example: you may want to add a new repository. Add the clone here
# Example: you may want to remove some of the rules available in the downloaded repositories. Remove them here.


# This script can be disabled during development using REPO_DOWNLOADER_ENABLED=true env variable
if [ "$REPO_DOWNLOADER_ENABLED" = "false" ]; then echo "Skipping repo_downloader.sh in DEVELOPMENT mode"; exit 0;  fi

# Download rules for quark-engine analyzer
cd ~
freshquark
# this is the default directory used by Quark-Engine
chown -R www-data:www-data ~/.quark-engine

# Clone dictionaries for dnstwist analyzer
cd /opt/deploy
svn export https://github.com/elceef/dnstwist/tags/20230402/dictionaries dnstwist-dictionaries

# download exiftool
# https://exiftool.org/install.html#Unix
mkdir exiftool_download
cd exiftool_download
version=$(curl https://exiftool.org/ver.txt)
echo "$version" >> exiftool_version.txt
wget "https://exiftool.org/Image-ExifTool-$version.tar.gz"
gzip -dc "Image-ExifTool-$version.tar.gz" | tar -xf -
cd "Image-ExifTool-$version"
chown -R www-data:www-data /opt/deploy/exiftool_download


