# 🛡️ Automated Cybersecurity Reference Sets

Automated daily mirror and aggregator of critical cybersecurity datasets. This project is designed to provide **simplified access** to reference lists, Threat Intelligence feeds, and "Living Off The Land" (LOL) binaries.

## ⚠️ Important Notice: Repository Reset
To maintain a lightweight repository size despite massive daily JSON datasets, **the git history is reset (force-pushed) every Sunday night**.
* **Previous versions are discarded.**
* If you clone this repository, you may need to run `git fetch --all && git reset --hard origin/main` or re-clone it weekly.

## 🔄 Automation & Data Engineering

To maintain high data integrity while respecting source constraints, the repository uses specialized GitHub Actions workflows:
* **Daily Updates:** High-churn IOCs (IPs, Domains, Hashes), CISA KEV, and EPSS scores.
* **Weekly Updates:** Large databases (GitHub Advisories, NVD full history) and website scraping (LOTS Project, MalAPI.io).
* **Smart Processing:**
    * **Compression:** Large datasets (like NVD or CPE dictionaries) are **GZIP-compressed (`.gz`)** to optimize bandwidth and storage.
    * **NVD CPE 2.0:** Automatically merges disjointed JSON chunks into a single Master Dictionary.
    * **Scraping:** Converts HTML tables from reference sites into machine-readable CSVs.
---

## 📂 Dataset Catalog

All processed files are stored in the `output/` directory and categorized below.

### 🦠 Threat Intelligence & IOCs
*Real-time indicators of compromise, botnets, and malware signatures.*

| File Name | Freq | Description | Source |
| :--- | :--- | :--- | :--- |
| `cisa_kev.json` | Daily | **Known Exploited Vulnerabilities**. Official catalog of CVEs exploited in the wild. | [CISA](https://www.cisa.gov/) |
| `malwarebazaar_daily_sample.csv` | Daily | **Malware Samples**. Daily batch of malware metadata. | [MalwareBazaar](https://bazaar.abuse.ch/) |
| `malwarebazaar_cscb.csv` | Daily | **Cert Blocklist**. Code Signing Certificates used by malware. | [MalwareBazaar](https://bazaar.abuse.ch/) |
| `malwarebazaar_yara_statistics.csv` | Daily | **YARA Stats**. Statistics on rule matches. | [MalwareBazaar](https://bazaar.abuse.ch/) |
| `threatfox_all_recent.json` | Daily | **IOC Feed**. Recent indicators (IP, Domain, Hash) for Botnets/Payloads. | [ThreatFox](https://threatfox.abuse.ch/) |
| `feodotracker_ipblocklist.json` | Weekly | **Botnet C2**. IP blocklist for Feodo/Dridex/Emotet. | [FeodoTracker](https://feodotracker.abuse.ch/) |
| `urlhaus_online.csv` | Weekly | **Malicious URLs**. Active malware distribution sites. | [URLhaus](https://urlhaus.abuse.ch/) |
| `openphish_community.list` | Weekly | **Phishing URLs**. Feed of currently active phishing sites. | [OpenPhish](https://openphish.com/) |
| `suspicious_mac_address_list.csv` | Weekly | **Suspicious MACs**. OUIs associated with malicious/spoofed devices. | [mthcht](https://github.com/mthcht/awesome-lists) |
| `suspicious_http_user_agents_lists.csv` | Weekly | **Bad User-Agents**. Signatures for scanners and bots. | [mthcht](https://github.com/mthcht/awesome-lists) |
| `suspicious_windows_services_names_list.csv` | Weekly | **Bad Services**. Windows service names used by malware. | [mthcht](https://github.com/mthcht/awesome-lists) |
| `suspicious_usb_ids_list.csv` | Weekly | **Bad USB IDs**. Hardware IDs of known malicious USB devices (Rubber Ducky, etc.). | [mthcht](https://github.com/mthcht/awesome-lists) |
| `lolc2_C2_data.json` | Weekly | **C2 Matrix**. Command & Control framework data. | [LOLC2](https://lolc2.github.io/) |

### 🛠️ Living Off The Land (LOL) & Tactics
*Legitimate tools and trusted sites abused by adversaries.*

| File Name | Freq | Description | Source |
| :--- | :--- | :--- | :--- |
| `filesec_project.csv` | Weekly | **File Extensions**. Extensions hijacked for code execution (CSV). | [FileSec.io](https://filesec.io/) |
| `lots_project.csv` | Weekly | **Trusted Sites**. Legitimate domains used for C2/Exfil (CSV). | [LOTS Project](https://lots-project.com/) |
| `malapi_windows_apis.csv` | Weekly | **WinAPI**. Windows functions abused by malware (CSV). | [MalAPI.io](https://malapi.io/) |
| `lottunnels_binaries.json` | Weekly | **Tunneling**. Binaries used for proxying traffic. | [LoTtunnels](https://github.com/LoTtunnels) |
| `lottunnels_domains.csv` | Weekly | **Tunneling Domains**. Domains associated with tunneling tools. | [LoTtunnels](https://github.com/LoTtunnels) |
| `lolbas.json` | Weekly | **Windows**. Living Off The Land Binaries/Scripts. | [LOLBAS](https://lolbas-project.github.io/) |
| `gtfobins_org.json` | Weekly | **Unix**. Binaries for privilege escalation/evasion. | [GTFOBins](https://gtfobins.org/) |
| `loobins_io.json` | Weekly | **macOS**. Living Off the Orchard Binaries. | [LOOBins](https://www.loobins.io/) |
| `loldrivers_io.json` | Weekly | **Drivers**. Vulnerable/Malicious Windows drivers. | [LOLDrivers](https://www.loldrivers.io/) |
| `lolrmm.json` | Weekly | **RMM**. Remote Monitoring & Management tools usage. | [LOLRMM](https://lolrmm.io/) |
| `lolesxi.json` | Weekly | **ESXi**. Binaries native to VMware ESXi. | [LOLESXi](https://lolesxi-project.github.io/LOLESXi/) |
| `bootloaders_io.json` | Weekly | **Bootloaders**. Known malicious bootloaders. | [Bootloaders.io](https://www.bootloaders.io/) |
| `loflcab.json` | Weekly | **Foreign Land**. Binaries executed in non-native contexts. | [LOFL](https://lofl-project.github.io/) |
| `mitre_attack_enterprise.json` | Weekly | **MITRE ATT&CK**. Full Enterprise Matrix. | [MITRE](https://attack.mitre.org/) |
| `exploitdb.csv` | Weekly | **Exploits**. Mapping of CVEs to Exploit-DB entries. | [ExploitDB](https://www.exploit-db.com/) |

### 🚨 Vulnerabilities & Scoring
*CVE databases and predictive scoring.*

| File Name | Freq | Description | Source |
| :--- | :--- | :--- | :--- |
| `epss_scores.csv.gz` | Daily | **EPSS**. Exploit Prediction Scoring System probabilities. | [FIRST.org](https://www.first.org/epss/) |
| `cwec_latest.xml` | Daily | **CWE**. Common Weakness Enumeration catalog. | [MITRE](https://cwe.mitre.org/) |
| `github_advisories.json` | Weekly | **GHSA**. Consolidated GitHub Security Advisories. | [GitHub](https://github.com/advisories) |
| `nvd_cpe_master_2.0.json.gz` | Weekly | **CPE Master**. Merged NIST dictionary of all products. | [NIST NVD](https://nvd.nist.gov/) |
| `nvdcve-2.0-*.json.gz` | Weekly | **CVE History**. Full NVD vulnerability feed (2002-Present). | [NIST NVD](https://nvd.nist.gov/) |
| `nvdcve-2.0-recent.json` | Weekly | **CVE Recent**. NVD feed for recent vulnerabilities. | [NIST NVD](https://nvd.nist.gov/) |

### 🌐 Network Infrastructure & Cloud
*IP ranges, anonymization nodes, and cloud service tags.*

| File Name | Freq | Description | Source |
| :--- | :--- | :--- | :--- |
| `tor_nodes_all.json` | Daily | **Tor**. All active Tor nodes details. | [Tor Project](https://onionoo.torproject.org/) |
| `tor_nodes_exit.json` | Daily | **Tor Exit**. Tor Exit nodes only. | [Tor Project](https://onionoo.torproject.org/) |
| `aws_ip_ranges.json` | Weekly | **AWS**. Amazon Web Services IP ranges. | [AWS](https://ip-ranges.amazonaws.com/ip-ranges.json) |
| `gcp_ip_ranges.json` | Weekly | **GCP**. Google Cloud Platform IP ranges. | [GCP](https://www.gstatic.com/ipranges/cloud.json) |
| `azure_ip_ranges.json` | Weekly | **Azure**. Microsoft Azure IP ranges & Service Tags. | [Enzo-G](https://github.com/enzo-g/azureIPranges) |
| `x4bnet_vpn_*.list` | Weekly | **VPN**. Datacenter and commercial VPN IP ranges. | [X4BNet](https://github.com/X4BNet/lists_vpn) |
| `protonvpn_all.json` | Weekly | **ProtonVPN**. Server list and IPs. | [Huzky](https://github.com/huzky-v/proton-vpn-server-list) |
| `tranco_top_1m_domains.csv` | Weekly | **Top 1M**. Tranco list of popular domains. | [Tranco](https://tranco-list.eu/) |
| `public_suffix.list` | Weekly | **TLDs**. Public Suffix List (effective TLDs). | [Mozilla](https://publicsuffix.org/) |
| `ip2asn-v4.tsv` | Weekly | **ASN**. IPv4 to ASN mapping. | [IPtoASN](https://iptoasn.com/) |
| `disposable_email_blocklist.list`| Weekly | **Temp Mail**. Disposable email domains. | [Disposable Domains](https://github.com/disposable-email-domains) |

### 🖥️ Hardware, Standards & Discovery
*Device identifiers, wordlists, and protocol registries.*

| File Name | Freq | Description | Source |
| :--- | :--- | :--- | :--- |
| `usb_ids.json` | Weekly | **USB**. Registry of USB Vendors and Products. | [Linux USB](http://www.linux-usb.org/) |
| `iana_service_ports.csv` | Weekly | **Ports**. IANA Service Name and Port Number Registry. | [IANA](https://www.iana.org/) |
| `standards_oui_ieee_*.csv` | Weekly | **MAC**. IEEE OUI/IAB/CID/MANID registries. | [IEEE](https://standards.ieee.org/) |
| `enesilhaydin_hardwares.json` | Weekly | **IoT**. IoT Hardware default credentials/info. | [Enesilhaydin](https://github.com/enesilhaydin/lothardware) |
| `hijacklibs.json` | Weekly | **DLL**. DLL Hijacking candidates. | [HijackLibs](https://hijacklibs.net/) |
| `seclists_*.list/csv` | Weekly | **Discovery**. Passwords, TLDs, Backdoors, Keywords. | [SecLists](https://github.com/danielmiessler/SecLists) |
| `mitchell_krog_*.list` | Weekly | **Web Sec**. Bad Referrers, User-Agents, Fake Bots. | [Bad Bot Blocker](https://github.com/mitchellkrogza) |

---

## ❤️ Community Acknowledgements

Cybref is built upon the incredible work of the global cybersecurity community. Massive thanks to the researchers, maintainers, and organizations who provide these critical datasets:

* **Threat Intelligence & Malware:**
    * **[Abuse.ch](https://abuse.ch/)** for their comprehensive ecosystem (MalwareBazaar, ThreatFox, FeodoTracker, URLhaus).
    * **[CISA](https://www.cisa.gov/)** for the KEV catalog.
    * **[FIRST.org](https://www.first.org/)** for the EPSS scoring system.
    * **[The Tor Project](https://www.torproject.org/)** for network transparency.
    * **[OpenPhish](https://openphish.com/)** and **[Exploit-DB](https://www.exploit-db.com/)** for community feeds.
    * **[mthcht](https://github.com/mthcht/awesome-lists)** for behavioral signatures (Suspicious MACs, User-Agents, Services).

* **Offensive Security & Living Off The Land (LOL):**
    * **The "LOL" Family:** [LOLBAS](https://lolbas-project.github.io/) (Windows), [GTFOBins](https://gtfobins.org/) (Unix), [LOOBins](https://www.loobins.io/) (macOS), [LOLDrivers](https://www.loldrivers.io/), [LOLRMM](https://lolrmm.io/), [LOLESXi](https://lolesxi-project.github.io/LOLESXi/), [LOFL](https://lofl-project.github.io/).
    * **Tactics & Hijacking:** [FileSec.io](https://filesec.io/) (Extensions), [LOTS Project](https://lots-project.com/) (Trusted Sites), [MalAPI.io](https://malapi.io/) (WinAPI), [LoTtunnels](https://github.com/LoTtunnels), [HijackLibs](https://hijacklibs.net/), [LOLC2](https://lolc2.github.io/), [Bootloaders.io](https://www.bootloaders.io/).

* **Vulnerabilities, Standards & Registries:**
    * **[NIST NVD](https://nvd.nist.gov/)** & **[MITRE](https://mitre.org/)** (ATT&CK, CWE) for global standards.
    * **[GitHub](https://github.com/advisories)** for the Advisory Database.
    * **[IANA](https://www.iana.org/)** & **[IEEE](https://standards.ieee.org/)** for core protocol and hardware registries.
    * **[Linux USB Project](http://www.linux-usb.org/)** for the USB ID repository.
    * **[Mozilla](https://publicsuffix.org/)** for the Public Suffix List.

* **Infrastructure, Cloud & Discovery:**
    * **Wordlists:** [Daniel Miessler](https://github.com/danielmiessler/SecLists) (SecLists), [Mitchell Krog](https://github.com/mitchellkrogza) (Bad Bot Blocker), [Enesilhaydin](https://github.com/enesilhaydin/lothardware) (IoT Hardware).
    * **Network:** [X4BNet](https://github.com/X4BNet/lists_vpn) (VPN Ranges), [Huzky](https://github.com/huzky-v/proton-vpn-server-list) (ProtonVPN), [Enzo-G](https://github.com/enzo-g/azureIPranges) (Azure Tags), [IPtoASN](https://iptoasn.com/), [Tranco](https://tranco-list.eu/) (Top 1M), [Disposable Domains](https://github.com/disposable-email-domains).

---

## ⚠️ Disclaimer

This repository automatically aggregates third-party data. The maintainers are not responsible for the accuracy or the use of this data. Always refer to the original project licenses before using these datasets in a commercial or production environment.