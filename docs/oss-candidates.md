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

## Initial upstream findings (2026-10-09; preliminary, not distribution clearance)

This is a source-backed **triage**, not a legal opinion. Exact revisions, dependency trees, and binary redistribution terms remain to be audited.

| Candidate | License evidence (upstream) | Preliminary decision | Commercial/reuse caution |
| --- | --- | --- | --- |
| Suricata | GPL-2.0 (source code; upstream license documentation) | **Integrate** EVE JSON from an independently deployed detector | Do not copy GPL-2.0 detector code into proprietary components without compatibility analysis; documentation has separate terms |
| Zeek | BSD family (upstream README; exact SPDX text to verify) | **Integrate** structured logs | Verify bundled/transitive code and notices before redistribution |
| Wazuh | GPL-2.0 (upstream API spec/package notice) | **Optional integration** via authenticated REST API | Overlaps with agentless-first goals; its agents are optional third-party integrations, not a Gorgoneion requirement |
| OpenCanary | BSD family (upstream pyproject; exact license file and notices to verify) | **Adopt as independent decoy** | Validate installation/telemetry and module-specific dependencies |
| Cowrie | BSD-3-Clause (upstream REUSE/SPDX declarations) | **Adopt as independent SSH/Telnet decoy** | Check dependency notices and ensure isolated lab deployment |
| OPNsense | BSD-2-Clause project; additional components have their own licenses | **Integrate via supported API** | Check API version and specific endpoint, avoid copying unrelated packages |
| nftables | license/package inventory still pending | **Integrate with host firewall tooling** | Use least privilege and bounded, reversible rules; do not assume its library license |

### Official upstream references
- Suricata source license: https://github.com/OISF/suricata/blob/main/doc/userguide/licenses/index.rst
- Zeek upstream repository: https://github.com/zeek/zeek
- Wazuh API specification: https://github.com/wazuh/wazuh/blob/main/api/api/spec/spec.yaml
- OpenCanary metadata: https://github.com/thinkst/opencanary/blob/master/pyproject.toml
- Cowrie REUSE/SPDX: https://github.com/cowrie/cowrie/blob/main/REUSE.toml
- OPNsense legal terms: https://docs.opnsense.org/legal.html

### Reuse architecture recommendation
1. **Gorgoneion controller** consumes standardized events; no replacement IDS, endpoint scanner, SSH server or firewall implementation.
2. **Dedicated adapters** normalize existing event output and call supported APIs; unit tests use fixtures/mock servers.
3. **Nemesys Engine** remains a narrow orchestration/authorization/auditing layer, initially strictly dry-run.
4. **OSS integration is never equal to blanket redistribution permission**; defer bundling until exact SPDX/SBOM, upstream revision, dependencies and commercial licensing review are complete.
5. **No real response action** until ownership scope, authorization, approval gates, rollback and logging have been tested.
