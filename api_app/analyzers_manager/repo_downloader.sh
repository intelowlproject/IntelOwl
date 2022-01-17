#!/bin/bash

# this is a simple script that downloads public yara repositories and make some changes on their configuration
# we have also added the download of other tools like quark-engine rules, dnstwist dictionaries and exiftool

# I suggest you to modify this script based on your needs.
# Example: you may want to add a new repository. Add the clone here
# Example: you may want to remove some of the rules available in the downloaded repositories. Remove them here.


# This script can be disabled during development using REPO_DOWNLOADER_ENABLED=true env variable
if [ "$REPO_DOWNLOADER_ENABLED" = "false" ]; then echo "Skipping repo_downloader.sh in DEVELOPMENT mode"; exit 0;  fi

cd /opt/deploy/yara

# Intezer rules
git clone --depth 1 https://github.com/intezer/yara-rules intezer_rules

# McAfee rules
git clone --depth 1 https://github.com/advanced-threat-research/Yara-Rules mcafee_rules

# Stratosphere rules
git clone --depth 1 https://github.com/stratosphereips/yara-rules stratosphere_rules

# ReversingLabs rules
git clone --depth 1 https://github.com/reversinglabs/reversinglabs-yara-rules reversinglabs_rules

# YaraHunts rules
git clone --depth 1 https://github.com/sbousseaden/YaraHunts samir_rules

# Inquest rules
git clone --depth 1 https://github.com/InQuest/yara-rules inquest_rules

# DailyIOC
git clone --depth 1 https://github.com/StrangerealIntel/DailyIOC daily_ioc_rules

# FireEye
git clone --depth 1 https://github.com/fireeye/red_team_tool_countermeasures fireeye_rules

# ATM Malware
git clone --depth 1 https://github.com/fboldewin/YARA-rules atm_malware_rules
rm -fr atm_malware_rules/*.md

# Yara community rules
git clone --depth 1 https://github.com/Yara-Rules/rules.git
community_yara_index="/opt/deploy/yara/rules/index.yar"

# remove broken or unwanted rules in Yara community rules
sed -i "/ELF/d" $community_yara_index
sed -i "/AZORULT/d" $community_yara_index
sed -i "/Operation_Blockbuster/d" $community_yara_index
sed -i "/MALW_ATM_HelloWorld.yar/d" $community_yara_index
sed -i "/MALW_Furtim/d" $community_yara_index
sed -i "/MALW_Naspyupdate.yar/d" $community_yara_index
sed -i "/APT_FIN7.yar/d" $community_yara_index
sed -i "/MalConfScan.yar/d" $community_yara_index
sed -i "/RAT_PoetRATPython.yar/d" $community_yara_index
sed -i "/Email_fake_it_maintenance_bulletin.yar/d" $community_yara_index
sed -i "/Email_quota_limit_warning.yar/d" $community_yara_index
sed -i "/RANSOM_acroware.yar/d" $community_yara_index
sed -i "/TOOLKIT_THOR_HackTools.yar/d" $community_yara_index

# Florian Roth rules
git clone --depth 1 https://github.com/Neo23x0/signature-base.git

# removed signatures that use external variables
cd /opt/deploy/yara/signature-base/yara
rm generic_anomalies.yar general_cloaking.yar thor_inverse_matches.yar yara_mixed_ext_vars.yar thor-webshells.yar

# Download rules for quark-engine analyzer
cd /opt/deploy
git clone https://github.com/quark-engine/quark-rules quark-rules
# this is done to lock the version since the repo does not have tags.
cd quark-rules
git checkout tags/0.0.1
# chown directories
chown -R www-data:www-data /opt/deploy/yara /opt/deploy/quark-rules

# Clone dictionaries for dnstwist analyzer
cd /opt/deploy
svn export https://github.com/elceef/dnstwist/tags/20201022/dictionaries dnstwist-dictionaries

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
