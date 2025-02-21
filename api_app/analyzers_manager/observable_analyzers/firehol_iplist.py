import ipaddress
import logging
import re

import dateparser

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.analyzers_manager.models import AnalyzerSourceFile, FireHolRecord

logger = logging.getLogger(__name__)


class FireHol_IPList(ObservableAnalyzer):
    regex_netstat = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}"
    regex_ip = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    base_url = (
        "https://raw.githubusercontent.com/firehol/blocklist-ipsets/refs/heads/master"
    )
    file_names = [
        "alienvault_reputation.ipset",
        "asprox_c2.ipset",
        "bambenek_banjori.ipset",
        "bambenek_bebloh.ipset",
        "bambenek_c2.ipset",
        "bambenek_cl.ipset",
        "bambenek_cryptowall.ipset",
        "bambenek_dircrypt.ipset",
        "bambenek_dyre.ipset",
        "bambenek_geodo.ipset",
        "bambenek_hesperbot.ipset",
        "bambenek_matsnu.ipset",
        "bambenek_necurs.ipset",
        "bambenek_p2pgoz.ipset",
        "bambenek_pushdo.ipset",
        "bambenek_pykspa.ipset",
        "bambenek_qakbot.ipset",
        "bambenek_ramnit.ipset",
        "bambenek_ranbyus.ipset",
        "bambenek_simda.ipset",
        "bambenek_suppobox.ipset",
        "bambenek_symmi.ipset",
        "bambenek_tinba.ipset",
        "bambenek_volatile.ipset",
        "bbcan177_ms1.netset",
        "bbcan177_ms3.netset",
        "bds_atif.ipset",
        "bitcoin_blockchain_info_1d.ipset",
        "bitcoin_blockchain_info_7d.ipset",
        "bitcoin_nodes.ipset",
        "bitcoin_nodes_1d.ipset",
        "bitcoin_nodes_7d.ipset",
        "blocklist_de_apache.ipset",
        "blocklist_de_bots.ipset",
        "blocklist_de_bruteforce.ipset",
        "blocklist_de_ftp.ipset",
        "blocklist_de_imap.ipset",
        "blocklist_de_mail.ipset",
        "blocklist_de_sip.ipset",
        "blocklist_de_ssh.ipset",
        "blocklist_de_strongips.ipset",
        "botscout.ipset",
        "botscout_1d.ipset",
        "botscout_7d.ipset",
        "botvrij_dst.ipset",
        "botvrij_src.ipset",
        "bruteforceblocker.ipset",
        "ciarmy.ipset",
        "cidr_report_bogons.netset",
        "cleanmx_phishing.ipset",
        "cleanmx_viruses.ipset",
        "cleantalk.ipset",
        "cleantalk_1d.ipset",
        "cleantalk_new.ipset",
        "cleantalk_new_1d.ipset",
        "cleantalk_new_7d.ipset",
        "cleantalk_top20.ipset",
        "coinbl_hosts.ipset",
        "coinbl_hosts_browser.ipset",
        "coinbl_hosts_optional.ipset",
        "coinbl_ips.ipset",
        "cruzit_web_attacks.ipset",
        "cta_cryptowall.ipset",
        "cybercrime.ipset",
        "darklist_de.netset",
        "datacenters.netset",
        "dm_tor.ipset",
        "dshield.netset",
        "dshield_1d.netset",
        "dshield_7d.netset",
        "dshield_top_1000.ipset",
        "dyndns_ponmocup.ipset",
        "esentire_14072015_com.ipset",
        "esentire_14072015q_com.ipset",
        "esentire_22072014a_com.ipset",
        "esentire_22072014b_com.ipset",
        "esentire_22072014c_com.ipset",
        "esentire_atomictrivia_ru.ipset",
        "esentire_auth_update_ru.ipset",
        "esentire_burmundisoul_ru.ipset",
        "esentire_crazyerror_su.ipset",
        "esentire_dagestanskiiviskis_ru.ipset",
        "esentire_differentia_ru.ipset",
        "esentire_disorderstatus_ru.ipset",
        "esentire_dorttlokolrt_com.ipset",
        "esentire_downs1_ru.ipset",
        "esentire_ebankoalalusys_ru.ipset",
        "esentire_emptyarray_ru.ipset",
        "esentire_fioartd_com.ipset",
        "esentire_getarohirodrons_com.ipset",
        "esentire_hasanhashsde_ru.ipset",
        "esentire_inleet_ru.ipset",
        "esentire_islamislamdi_ru.ipset",
        "esentire_krnqlwlplttc_com.ipset",
        "esentire_maddox1_ru.ipset",
        "esentire_manning1_ru.ipset",
        "esentire_misteryherson_ru.ipset",
        "esentire_mysebstarion_ru.ipset",
        "esentire_smartfoodsglutenfree_kz.ipset",
        "esentire_venerologvasan93_ru.ipset",
        "esentire_volaya_ru.ipset",
        "et_block.netset",
        "et_botcc.ipset",
        "et_compromised.ipset",
        "et_dshield.netset",
        "et_spamhaus.netset",
        "et_tor.ipset",
        "feodo.ipset",
        "feodo_badips.ipset",
        "firehol_abusers_1d.netset",
        "firehol_level1.netset",
        "firehol_level2.netset",
        "firehol_level3.netset",
        "firehol_level4.netset",
        "firehol_webclient.netset",
        "firehol_webserver.netset",
        "gpf_comics.ipset",
        "graphiclineweb.netset",
        "greensnow.ipset",
        "haley_ssh.ipset",
        "hphosts_ats.ipset",
        "hphosts_emd.ipset",
        "hphosts_exp.ipset",
        "hphosts_fsa.ipset",
        "hphosts_grm.ipset",
        "hphosts_hfs.ipset",
        "hphosts_hjk.ipset",
        "hphosts_mmt.ipset",
        "hphosts_pha.ipset",
        "hphosts_psh.ipset",
        "hphosts_wrz.ipset",
        "iblocklist_abuse_palevo.netset",
        "iblocklist_abuse_spyeye.netset",
        "iblocklist_abuse_zeus.netset",
        "iblocklist_ciarmy_malicious.netset",
        "iblocklist_cidr_report_bogons.netset",
        "iblocklist_cruzit_web_attacks.netset",
        "iblocklist_isp_aol.netset",
        "iblocklist_isp_att.netset",
        "iblocklist_isp_cablevision.netset",
        "iblocklist_isp_charter.netset",
        "iblocklist_isp_comcast.netset",
        "iblocklist_isp_embarq.netset",
        "iblocklist_isp_qwest.netset",
        "iblocklist_isp_sprint.netset",
        "iblocklist_isp_suddenlink.netset",
        "iblocklist_isp_twc.netset",
        "iblocklist_isp_verizon.netset",
        "iblocklist_malc0de.netset",
        "iblocklist_onion_router.netset",
        "iblocklist_org_activision.netset",
        "iblocklist_org_apple.netset",
        "iblocklist_org_blizzard.netset",
        "iblocklist_org_crowd_control.netset",
        "iblocklist_org_electronic_arts.netset",
        "iblocklist_org_joost.netset",
        "iblocklist_org_linden_lab.netset",
        "iblocklist_org_logmein.netset",
        "iblocklist_org_ncsoft.netset",
        "iblocklist_org_nintendo.netset",
        "iblocklist_org_pandora.netset",
        "iblocklist_org_pirate_bay.netset",
        "iblocklist_org_punkbuster.netset",
        "iblocklist_org_riot_games.netset",
        "iblocklist_org_sony_online.netset",
        "iblocklist_org_square_enix.netset",
        "iblocklist_org_steam.netset",
        "iblocklist_org_ubisoft.netset",
        "iblocklist_org_xfire.netset",
        "iblocklist_pedophiles.netset",
        "iblocklist_spamhaus_drop.netset",
        "iblocklist_yoyo_adservers.netset",
        "ipblacklistcloud_recent.ipset",
        "ipblacklistcloud_recent_1d.ipset",
        "ipblacklistcloud_recent_7d.ipset",
        "ipblacklistcloud_top.ipset",
        "iw_spamlist.ipset",
        "iw_wormlist.ipset",
        "lashback_ubl.ipset",
        "malc0de.ipset",
        "malwaredomainlist.ipset",
        "maxmind_proxy_fraud.ipset",
        "myip.ipset",
        "nixspam.ipset",
        "normshield_all_attack.ipset",
        "normshield_all_bruteforce.ipset",
        "normshield_all_ddosbot.ipset",
        "normshield_all_dnsscan.ipset",
        "normshield_all_spam.ipset",
        "normshield_all_suspicious.ipset",
        "normshield_all_wannacry.ipset",
        "normshield_all_webscan.ipset",
        "normshield_all_wormscan.ipset",
        "normshield_high_attack.ipset",
        "normshield_high_bruteforce.ipset",
        "normshield_high_ddosbot.ipset",
        "normshield_high_dnsscan.ipset",
        "normshield_high_spam.ipset",
        "normshield_high_suspicious.ipset",
        "normshield_high_wannacry.ipset",
        "normshield_high_webscan.ipset",
        "normshield_high_wormscan.ipset",
        "nt_malware_dns.ipset",
        "nt_malware_http.ipset",
        "nt_malware_irc.ipset",
        "nt_ssh_7d.ipset",
        "nullsecure.ipset",
        "packetmail.ipset",
        "packetmail_emerging_ips.ipset",
        "packetmail_mail.ipset",
        "packetmail_ramnode.ipset",
        "php_commenters.ipset",
        "php_commenters_1d.ipset",
        "php_commenters_7d.ipset",
        "php_dictionary.ipset",
        "php_dictionary_1d.ipset",
        "php_dictionary_7d.ipset",
        "php_harvesters.ipset",
        "php_harvesters_1d.ipset",
        "php_harvesters_7d.ipset",
        "php_spammers.ipset",
        "php_spammers_1d.ipset",
        "php_spammers_7d.ipset",
        "proxylists.ipset",
        "proxylists_1d.ipset",
        "proxylists_7d.ipset",
        "proxyspy_1d.ipset",
        "proxyspy_7d.ipset",
        "proxz.ipset",
        "proxz_1d.ipset",
        "proxz_7d.ipset",
        "pushing_inertia_blocklist.netset",
        "ransomware_cryptowall_ps.ipset",
        "ransomware_feed.ipset",
        "ransomware_locky_c2.ipset",
        "ransomware_locky_ps.ipset",
        "ransomware_online.ipset",
        "ransomware_rw.ipset",
        "ransomware_teslacrypt_ps.ipset",
        "ransomware_torrentlocker_c2.ipset",
        "ransomware_torrentlocker_ps.ipset",
        "sblam.ipset",
        "set_file_timestamps.sh",
        "snort_ipfilter.ipset",
        "socks_proxy.ipset",
        "socks_proxy_1d.ipset",
        "socks_proxy_7d.ipset",
        "spamhaus_drop.netset",
        "spamhaus_edrop.netset",
        "sslbl.ipset",
        "sslbl_aggressive.ipset",
        "sslproxies.ipset",
        "sslproxies_1d.ipset",
        "sslproxies_7d.ipset",
        "stopforumspam_1d.ipset",
        "taichung.ipset",
        "talosintel_ipfilter.ipset",
        "threatcrowd.ipset",
        "tor_exits.ipset",
        "tor_exits_1d.ipset",
        "tor_exits_7d.ipset",
        "turris_greylist.ipset",
        "urandomusto_dns.ipset",
        "urandomusto_ftp.ipset",
        "urandomusto_http.ipset",
        "urandomusto_mailer.ipset",
        "urandomusto_malware.ipset",
        "urandomusto_ntp.ipset",
        "urandomusto_rdp.ipset",
        "urandomusto_smb.ipset",
        "urandomusto_spam.ipset",
        "urandomusto_ssh.ipset",
        "urandomusto_telnet.ipset",
        "urandomusto_unspecified.ipset",
        "urandomusto_vnc.ipset",
        "urlvir.ipset",
        "uscert_hidden_cobra.ipset",
        "voipbl.netset",
        "vxvault.ipset",
        "xforce_bccs.ipset",
        "xroxy.ipset",
        "xroxy_1d.ipset",
        "xroxy_7d.ipset",
        "yoyo_adservers.ipset",
    ]

    def run(self) -> dict:
        result = {"found": False}

        records = FireHolRecord.objects.filter(
            ip_start__lte=self.observable_name, ip_end__gte=self.observable_name
        ).values()

        categories = {}
        for rec in records:
            try:
                categories[rec["category"]].append(
                    {
                        "source": rec["source"],
                        "file_date": rec["file_date"].strftime("%Y-%m-%d %H:%M:%S"),
                        "last_update": rec["last_update"].strftime("%Y-%m-%d %H:%M:%S"),
                        "ip_start": rec["ip_start"],
                        "ip_end": rec["ip_end"],
                    }
                )
            except KeyError:
                categories[rec["category"]] = [
                    {
                        "source": rec["source"],
                        "file_date": rec["file_date"].strftime("%Y-%m-%d %H:%M:%S"),
                        "last_update": rec["last_update"].strftime("%Y-%m-%d %H:%M:%S"),
                        "ip_start": rec["ip_start"],
                        "ip_end": rec["ip_end"],
                    }
                ]
        if categories:
            result["found"] = True
            result["categories"] = categories

        return result

    @classmethod
    def update(cls) -> bool:
        general_update = False
        for file_name in cls.file_names:
            request_data = {"url": f"{cls.base_url}/{file_name}"}
            update = cls.update_internal_data(
                request_data,
                file_name,
            )
            if update:
                general_update = True
        return general_update

    @classmethod
    def update_support_model(cls, file_name):
        source_file = AnalyzerSourceFile.objects.filter(
            file_name=file_name, python_module=cls.python_module
        ).first()

        if ".ipset" in file_name:
            source = file_name.replace(".ipset", "")
            netstat = False
        elif ".netset" in file_name:
            source = file_name.replace(".netset", "")
            netstat = True
        else:
            return

        comments, ips = [], []
        for line in source_file.file.readlines():
            line = line.decode()
            comments.append(line) if line.startswith("#") else ips.append(line)

        category = None
        file_date = None
        for line in comments:
            if "# Source File Date: " in line:
                datestr = re.sub("# Source File Date: ", "", line.rstrip("\n"))
                parsed_date = dateparser.parse(datestr)
                file_date = parsed_date
            match_category = re.search(r"Category\s+:\s(\w+)", line.rstrip("\n"))
            if match_category:
                category = match_category.group(1)
                if category:
                    break

        records = {}
        # iterating over IP addresses extracted from the file
        for i, line in enumerate(ips):

            # calculate IP range
            if netstat:
                ip_address_found = re.search(
                    cls.regex_netstat,
                    line,
                )
                if not ip_address_found:
                    logger.info(
                        f"Can't find ip address, line is {line} in file {file_name}"
                    )
                    continue

                ip_address_found = ipaddress.IPv4Network(ip_address_found.group())
                ip_start = str(ip_address_found.network_address)
                ip_end = str(ip_address_found.broadcast_address)
            else:
                ip_address_found = re.search(cls.regex_ip, line)
                if not ip_address_found:
                    logger.info(
                        f"Can't find ip address, line is {line} in file {file_name}"
                    )
                    continue
                ip_start = ip_end = ip_address_found.group()

            data = {
                "source": source,
                "category": category,
                "file_date": file_date,
                "ip_start": ip_start,
                "ip_end": ip_end,
            }
            records[(source, ip_start, ip_end, category)] = data

        FireHolRecord.generate(list(records.values()))
