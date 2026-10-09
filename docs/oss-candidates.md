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

## Mandatory evaluation process

1. **Search first:** identify candidate upstream OSS by feature, not by preferred programming language. Prefer mature maintained projects and official APIs.
2. **Examine suitability:** functionality, operational model (server/agentless-first), security posture, maintenance cadence, compatibility and integration cost.
3. **Check rights:** exact SPDX license, transitive licenses, patents/trademarks as relevant, source/notice obligations and viability for future paid distributions. For GPL/AGPL and other copyleft licenses, evaluate actual combined-work/deployment implications; a process boundary is not automatically sufficient.
4. **Choose least reinvention:** use an existing deployment or adapter, incorporate a compatible library, adapt/fork with tracked upstream commits, or implement only the uncovered component.
5. **Record evidence:** compare candidates, select a decision, document rejected alternatives, upstream URLs, versions, licenses, security/maintenance risks, and update plan.
6. **Maintain:** pin versions, track advisories, refresh SBOM and notices, test upstream changes and contribute fixes upstream when appropriate.

Every implementation issue/PR must link to the evaluation or explicitly state why existing alternatives were insufficient. Do **not** claim that all open-source code is available for proprietary redistribution: use rights must be checked per component and distribution model.

## Integration priority for v0.1

Focus new code on **Gorgoneion-specific orchestration, authorization policy, audit and a minimal event normalization layer**. Reuse Suricata/Zeek etc. for detection rather than authoring a new IDS. Prefer standard formats and existing libraries for parsing, CLI, serialization, observability and SBOM generation.
