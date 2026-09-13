# Playbook: Suspected Identity Compromise (Defender + Entra)

**Classification:** [TEMPLATE]

1. Review risky sign-ins and impossible travel.
2. Confirm MFA fatigue / token theft indicators.
3. Contain: revoke sessions, reset password, require MFA re-register (IAM approval).
4. Hunt devices used during compromise window with KQL.
5. Check OAuth app consent grants for suspicious apps.
6. Close with user communication and detection tuning notes.
