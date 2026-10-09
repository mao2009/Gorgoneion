# Existing OSS candidates — evaluation required

**Candidate list, not approval to import or redistribute.** Record exact upstream revision, SPDX license expression, copyright, dependencies, network architecture, maintenance and security posture for every candidate.

| Project | Potential use | Initial integration approach |
| --- | --- | --- |
| Suricata | IDS/IPS event stream | EVE JSON/log ingestion |
| Zeek | Network event analytics | Event/log ingestion |
| Wazuh | Security event response ecosystem | API/event integration |
| OpenCanary | Low-interaction honeypot | Controlled adapter |
| Cowrie | SSH/Telnet honeypot | Controlled adapter |
| nftables | Linux firewall | Strictly authorized rules via managed gateway |
| OPNsense | Managed firewall appliance | Official API adapter |

An external process boundary is **not an automatic license-compliance exemption**. Verify licensing and distribution model before shipping integrations or vendored code. Preserve notices and build an SPDX SBOM before release.
