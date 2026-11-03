# 🦅 CrowdStrike Engineering

Dashboards, widgets, and queries for the CrowdStrike Falcon platform, built for real SOC and threat hunting work.

More engineering content coming soon.

---

## 📊 Dashboards

| Dashboard | What it does | Version |
| --- | --- | --- |
| 🩺 [Endpoint Security](EndpointSecurity-Dashboard.md) | Sensor health and coverage: who's reporting, who's gone silent, and what's out of date | v1 |
| 🔎 [Daily Threat Hunts](ThreatHuntV2-Dashboard.md) | 17 daily hunts across execution, identity, persistence, and lateral movement | v2 |
| 🗄️ [Threat Hunt – Pilot](ThreatHunt-Dashboard.md) | Original 7-hunt pilot, kept for history | v1 |

---

## 🎯 Approach

Detections catch what someone already wrote a rule for. The hunts here go after the rest: unusual activity for an analyst to investigate, without adding to alert fatigue. Anything that proves high-fidelity gets promoted into a scheduled search or custom IOA.

---

## 📌 Notes

- Every dashboard is documented with the CQL behind each widget.
- Queries are starting points. Field names, exclusions, and approved-tool lists are environment-specific and need tuning.
- Hunts surface activity for human review. They don't alert or take action on their own.