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

### 🛠️ Living Off The Land (LOL) & Binaries
*Legitimate tools and functions abused by adversaries for C2, exfiltration, or evasion.*

| File Name | Description | Source |
| :--- | :--- | :--- |
| `lots_project.csv` | **Scraped**. Legitimate domains (Google, Azure, etc.) used for malicious purposes. | [LOTS Project](https://lots-project.com/) |
| `malapi_windows_apis.csv` | **Scraped**. Windows API functions commonly abused by malware. | [MalAPI.io](https://malapi.io/) |
| `lottunnels_binaries.json` | **Parsed**. Binaries used for tunneling and proxying. | [LoTtunnels](https://github.com/LoTtunnels) |
| `lolbas.json` | Windows binaries, scripts, and libraries (Living Off The Land). | [LOLBAS](https://lolbas-project.github.io/) |
| `gtfobins_org.json` | Unix-like binaries for privilege escalation and evasion. | [GTFOBins](https://gtfobins.org/) |
| `loldrivers_io.json` | Vulnerable and malicious Windows drivers. | [LOLDrivers](https://www.loldrivers.io/) |
| `lolrmm.json` | Remote Monitoring and Management (RMM) tools. | [LOLRMM](https://lolrmm.io/) |

### 🦠 Threat Intelligence & Behavioral Lists
*Indicators of Compromise and suspicious behavior signatures.*

| File Name | Description | Source |
| :--- | :--- | :--- |
| `feodotracker_ipblocklist.json` | Botnet C2 IP addresses. | [Abuse.ch](https://feodotracker.abuse.ch/) |
| `urlhaus_online.csv` | Active malware distribution URLs. | [URLhaus](https://urlhaus.abuse.ch/) |
| `theathox_all_recent.json` | Recent IoT Botnet indicators. | [ThreatFox](https://threatfox.abuse.ch/) |
| `suspicious_http_user_agents.csv`| Behavioral signatures for malicious web traffic. | [mthcht](https://github.com/mthcht/awesome-lists) |
| `suspicious_windows_services.csv`| List of suspicious Windows service names. | [mthcht](https://github.com/mthcht/awesome-lists) |
| `mitre_attack_enterprise.json` | MITRE ATT&CK Matrix (Enterprise). | [MITRE CTI](https://github.com/mitre/cti) |

### 🚨 Vulnerabilities & CVE History
*The complete National Vulnerability Database and exploit metadata.*

| File Name | Description | Source |
| :--- | :--- | :--- |
| `nvdcve-2.0-*.json.gz` | **Full History**. NVD JSON feeds from 2012 to 2026 (not extracted). | [NIST NVD](https://nvd.nist.gov/) |
| `github_advisories.json` | **Consolidated**. All GitHub-reviewed security advisories. | [GitHub Advisory](https://github.com/advisories) |
| `cisa_kev.json` | CISA Known Exploited Vulnerabilities catalog. | [CISA](https://www.cisa.gov/) |
| `epss_scores.csv` | Exploit Prediction Scoring System probabilities. | [FIRST.org](https://www.first.org/epss/) |
| `exploitdb.csv` | Mapping of CVEs to public exploit code. | [ExploitDB](https://www.exploit-db.com/) |

### 🖥️ Hardware & Infrastructure
*MAC addresses, USB identifiers, and Cloud IP ranges.*

| File Name | Description | Source |
| :--- | :--- | :--- |
| `usb_ids.json` | **Generated**. Official USB Vendor and Product ID database. | [Linux USB](http://www.linux-usb.org/) |
| `standards_oui_ieee_*.csv` | IEEE MAC address registration data (OUI/IAB/CID). | [IEEE Standards](https://standards.ieee.org/) |
| `azure_ip_ranges.json` | Microsoft Azure Service Tags and IP ranges. | [Enzo-G / MSFT](https://enzo-g.github.io/azureIPranges/) |
| `aws_ip_ranges.json` | Amazon Web Services official IP ranges. | [AWS](https://ip-ranges.amazonaws.com/ip-ranges.json) |

---

## ❤️ Community Acknowledgements

This project would not exist without the tireless work of the global cybersecurity community. We want to thank and credit the following maintainers:

* **Abuse.ch** (FeodoTracker, ThreatFox, MalwareBazaar, URLhaus) for their vital IOC feeds.
* **The LOLBAS & GTFOBins teams** for pioneering the Living Off The Land documentation.
* **NIST** for maintaining the National Vulnerability Database.
* **MITRE Corporation** for the ATT&CK framework.
* **GitHub Security** for the Advisory Database.
* **mthcht** for the incredible "Awesome-lists" repository and behavioral signatures.
* **CISA** for the KEV Catalog.
* **Daniel Miessler** for SecLists.
* **LoTtunnels, LOOBins, LOLDrivers, LOLRMM** projects for their specialized research.
* **The IEEE & Linux USB Project** for hardware standard maintenance.

---

## ⚠️ Disclaimer

This repository automatically aggregates third-party data. The maintainers are not responsible for the accuracy or the use of this data. Always refer to the original project licenses before using these datasets in a commercial or production environment.