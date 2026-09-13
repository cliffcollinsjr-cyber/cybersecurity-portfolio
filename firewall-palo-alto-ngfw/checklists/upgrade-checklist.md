# Upgrade Checklist — PAN-OS

**Classification:** [TEMPLATE]

1. Read release notes / known issues for target version.
2. Validate preferred release from vendor guidance.
3. Backup config + export tech support file if needed.
4. Check content update compatibility.
5. Upgrade passive HA peer first (if HA); verify; failover; upgrade former active.
6. Functional test: critical apps, VPN, User-ID, logging to SIEM.
7. Monitor threat/traffic logs 24h post-upgrade.
