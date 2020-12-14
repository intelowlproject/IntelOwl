#!/bin/bash

# this is a simple script that downloads public yara repositories and make some changes on their configuration

# I suggest you to modify this script based on your needs.
# Example: you may want to add a new repository. Add the clone here
# Example: you may want to remove some of the rules available in the downloaded repositories. Remove them here.

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
svn export https://github.com/quark-engine/quark-engine/tags/v20.08/quark/rules quark-rules

# chown directories
chown -R www-data:www-data /opt/deploy/yara /opt/deploy/quark-rules

# Clone dictionaries for dnstwist analyzer
svn export https://github.com/elceef/dnstwist/tags/20201022/dictionaries dnstwist-dictionaries