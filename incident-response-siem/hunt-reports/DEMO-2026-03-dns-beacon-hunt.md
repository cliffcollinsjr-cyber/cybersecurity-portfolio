# Threat Hunt Report — Periodic DNS / Possible Beaconing

| Field | Value |
|-------|-------|
| **Classification** | `[DEMO]` — synthetic lab narrative |
| **Hunt ID** | `HUNT-DEMO-2026-03-014` |
| **Analyst** | Cliff Collins Jr |
| **Date** | 2026-03-14 |
| **Environment** | Lab SIEM (Splunk) + DNS logs |
| **Status** | Closed — detection candidate opened |

---

## 1. Hypothesis

Hosts that perform **low-variance, near-periodic DNS queries** to a **small set of rare domains** over sustained windows may be exhibiting C2-style beaconing or misconfigured agents. We hunt for that pattern without assuming malware family.

**Why now:** Recent malware playbook reviews showed gaps between “known bad domain” IOC hits and behavioral DNS anomalies.

## 2. Scope & data sources

| Source | Index / type `[DEMO]` | Fields used |
|--------|------------------------|-------------|
| Internal DNS | `index=dns` `sourcetype=dns:query` | `_time`, `src_ip`, `query` |
| DHCP / asset inventory | `index=asset` (join optional) | `src_ip`, `hostname`, `owner` |
| Proxy (validation) | `index=proxy` | `url`, `src_ip` |

**Time range:** 7 days rolling.  
**Out of scope:** Blocking domains; host isolation without IR approval.

## 3. Hunt methodology

1. Build candidate set with statistical DNS periodicity heuristic (see query).
2. Enrich with asset owner / role (server vs workstation).
3. Spot-check top domains for age, category, and known-good software.
4. Correlate survivors with process/EDR if available (handoff to Defender/Falcon).
5. Document FP classes; propose tuned detection.

## 4. Primary query (Splunk SPL)

Canonical copy: [`../splunk-queries/dns_beacon_suspect.spl`](../splunk-queries/dns_beacon_suspect.spl)

```spl
index=dns sourcetype=dns:query
| bin _time span=1m
| stats count as qpm by src_ip, query, _time
| stats avg(qpm) as avg_qpm, stdev(qpm) as std_qpm, count as intervals, dc(query) as unique_queries by src_ip
| where intervals > 30 AND std_qpm < 0.5 AND unique_queries < 5
| sort - intervals
| head 25
```

## 5. Findings `[DEMO]`

| Rank | Host / IP | Pattern | Verdict |
|------|-----------|---------|---------|
| 1 | `wrk-0421` / `10.20.8.41` | ~1 qpm to `upd-cdn-lab.example` for 6d | **Benign** — vendor update agent (documented) |
| 2 | `lab-win10-07` / `10.20.12.77` | Steady queries to newly registered DGA-like label | **Suspicious** — escalated to IR case `IR-DEMO-4412` |
| 3 | `prn-floor3` / `10.20.50.12` | Low unique queries, high periodicity | **Benign** — printer telemetry DNS |

**True-positive candidate:** `lab-win10-07` also showed rare outbound HTTPS later in proxy logs (same day). Contained via standard compromised-host playbook in lab.

## 6. False positives & tuning

| FP class | Mitigation |
|----------|------------|
| Update / MDM / AV telemetry | Allowlist known software domains + signed agent processes |
| Short-lived DHCP reuse | Require ≥24h of history before alerting |
| Low-traffic IoT | Separate baseline per asset class |

**Proposed detection:** Correlation search with asset-class baselines + deny-list of known-good query names; alert only when rare domain AND periodicity AND no matching allowlisted process (EDR join).

## 7. Outcomes & follow-ups

- [x] Hypothesis tested in lab
- [x] One suspicious host escalated (DEMO case)
- [x] Detection engineering ticket: tune SPL + add domain age enrichment
- [ ] Production enablement — **not applicable** (DEMO only)

## 8. Lessons learned

Behavioral DNS hunts need **asset context** early; raw periodicity alone is noisy. Pairing Splunk candidates with EDR process lineage closed FP faster than domain intel alone.
