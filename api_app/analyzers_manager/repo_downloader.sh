#!/bin/bash

# this is a simple script that downloads public yara repositories and make some changes on their configuration
# we have also added the download of other tools like quark-engine rules, dnstwist dictionaries and exiftool

# I suggest you to modify this script based on your needs.
# Example: you may want to add a new repository. Add the clone here
# Example: you may want to remove some of the rules available in the downloaded repositories. Remove them here.

# This script can be disabled during development using REPO_DOWNLOADER_ENABLED=true env variable
if [ "$REPO_DOWNLOADER_ENABLED" = "false" ]; then echo "Skipping repo_downloader.sh in DEVELOPMENT mode"; exit 0; fi

# Download rules for quark-engine analyzer
cd ~ || exit
freshquark
# this is the default directory used by Quark-Engine
chown -R www-data:www-data ~/.quark-engine

# Clone dictionaries for dnstwist analyzer
cd /opt/deploy || exit

DNSTWIST_RAW_BASE="https://raw.githubusercontent.com/elceef/dnstwist/master/dictionaries"

mkdir -p dnstwist-dictionaries

curl -fSL "$DNSTWIST_RAW_BASE/abused_tlds.dict" \
  -o dnstwist-dictionaries/abused_tlds.dict

curl -fSL "$DNSTWIST_RAW_BASE/common_tlds.dict" \
  -o dnstwist-dictionaries/common_tlds.dict


# download exiftool
# https://exiftool.org/install.html#Unix
# Define directories for clarity
DOWNLOAD_DIR="exiftool_download"
DEPLOY_DIR="/opt/deploy/exiftool_download"

# 1. Create and enter directory
mkdir -p "$DOWNLOAD_DIR" || { echo "Failed to create directory"; exit 1; }
cd "$DOWNLOAD_DIR" || { echo "Failed to enter directory"; exit 1; }

# 2. Get version with error handling
version=$(curl -s https://exiftool.org/ver.txt)
if [[ -z "$version" ]]; then
    echo "Error: Could not retrieve version number."
    exit 1
fi
echo "$version" >> exiftool_version.txt

# 3. Handle wget errors
# -q: quiet, -O: output file.
# The tarball is no longer served from exiftool.org (that path now 404s);
# exiftool.org itself links downloads to SourceForge. That URL ends in
# "/download" and redirects to a mirror, so -O pins the expected filename
# for the extraction step below.
# Checking if the file actually exists after the command
if ! wget -q -O "Image-ExifTool-$version.tar.gz" "https://sourceforge.net/projects/exiftool/files/Image-ExifTool-$version.tar.gz/download"; then
    echo "Error: Failed to download ExifTool version $version."
    exit 1
fi

# 4. Handle extraction errors
if ! gzip -dc "Image-ExifTool-$version.tar.gz" | tar -xf -; then
    echo "Error: Failed to extract files."
    exit 1
fi

# 5. Handle directory navigation and permissions
cd "Image-ExifTool-$version" || { echo "Failed to enter extracted directory"; exit 1; }
chown -R www-data:www-data "$DEPLOY_DIR" || { echo "Warning: chown failed (check sudo permissions)"; }

echo "ExifTool $version deployed successfully."
