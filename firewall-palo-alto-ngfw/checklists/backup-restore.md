# Backup & Restore Checklist — PAN-OS / Panorama

**Classification:** [TEMPLATE]

## Backup

- [ ] Scheduled config export / Panorama backups verified
- [ ] Export named config snapshot before change window
- [ ] Store encrypted off-box; access controlled
- [ ] Validate backup freshness (< 24h for critical devices)

## Restore (authorized maintenance only)

- [ ] Confirm target device serial / HA role
- [ ] Import candidate config to candidate (not auto-commit)
- [ ] Diff against running; peer review
- [ ] Commit / push during window
- [ ] Validate HA sync, interfaces, VPN, critical allows
- [ ] Document restore ticket
