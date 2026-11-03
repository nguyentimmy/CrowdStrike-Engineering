# 🦅 CrowdStrike Engineering

Dashboards, widgets, and queries for the CrowdStrike Falcon platform, built for real SOC and threat hunting work.

More engineering content coming soon.

---

## 📊 Dashboards

| Dashboard | What it does 
| --- | --- | --- |
| 🛡️ [Endpoint Defense Posture](EndpointDefensePosture-Dashboard.md) | All-in-one view of endpoint protection: sensor health, detection trends, custom IOA/IOC health, and prevention coverage 
| 🩺 [Sensor Health](SensorHealth-Dashboard.md) | Sensor coverage and health: who's reporting, who's gone silent, and what's out of date 
| 🔎 [Daily Threat Hunts](ThreatHuntV2-Dashboard.md) | 17 daily hunts across execution, identity, persistence, and lateral movement 
| 🗄️ [Daily Threat Hunts v1 (OG)](ThreatHunt-Dashboard.md) | Original 7-hunt pilot, kept for history 
---

## 🎯 Approach

Detections catch what someone already wrote a rule for. This repo covers both sides:

- **Hunting** finds the noisy and undetected activity that alerts miss, as leads for an analyst to investigate without adding to alert fatigue.
- **Posture** checks the protection itself: sensors running everywhere, rules tuned, and prevention actually on.

Anything that proves high-fidelity gets promoted into a scheduled search or custom IOA.

---

## 🗂️ What's in each dashboard doc

- Why it exists and what question it answers
- Parameters and recommended time range
- The CQL behind every widget, with the chart type to use
- How to use it, and notes on tuning

---

## 🔜 Coming soon

- Importable dashboard templates (YAML)
- More dashboards and widgets
- Other engineering content

---

## 📌 Notes

- Queries are starting points. Field names, exclusions, and approved-tool lists are environment-specific and need tuning before use.
- Hunts surface activity for human review. They don't alert or take action on their own.
