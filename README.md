# 🦅 CrowdStrike Engineering

CrowdStrike Falcon dashboards, widgets, hunting queries, and custom detections, built from real SOC work.

The focus: find the activity alerts miss, check that protection is actually working, and keep triage fast, without adding to alert fatigue.

---

## 🗂️ Repo layout

| Folder | What's inside |
| --- | --- |
| 📊 [CS Dashboards](<CS Dashboards 📊/>) | Falcon dashboards, each documented with the CQL behind every widget |
| 🐦‍🔥 [CS Detection](<CS Detection 🐦‍🔥/>) | Custom IOAs and correlation rules, promoted from hunts that proved high-fidelity |

---

## 📊 Dashboards

| Dashboard | What it does |
| --- | --- |
| **🛡️ Endpoint Security** | |
| [Endpoint Defense Posture](<CS Dashboards 📊/Endpoint Security/EndpointDefensePosture.md>) | All-in-one view: sensor health, detection trends and timeline, custom IOA/IOC health, and prevention coverage |
| [Sensor Health Telemetry](<CS Dashboards 📊/Endpoint Security/SensorHealthTelemetry.md>) | Who's reporting, who's gone silent, who's flapping, and what's out of date |
| **🔎 Security Operations** | |
| [Hunt & Response](<CS Dashboards 📊/Security Operations/Hunt&Response.md>) | Hunts for undetected activity fleet-wide, and audits a compromised host for the IR report |
| [Triage Detection](<CS Dashboards 📊/Security Operations/TriageDetection.md>) | Detection timeline, host attack path, multi-tactic hosts, and tuning KPIs |

---

## 🎯 Approach

- **Hunt & Response** surfaces noisy and undetected activity as leads, then audits a compromised host end to end.
- **Posture** checks the protection itself: sensors running everywhere, rules tuned, prevention on.
- **Detection** is where proven hunts end up, as custom rules that fire on their own.

---

## ⚙️ Requirements

- Built for **Falcon Next-Gen SIEM / Advanced event search** (CQL).
- Hunts are Windows-focused.
- Event names and fields can differ between tenants, data sources, and licensed modules. Verify on one raw event before saving a widget.

---

## 📌 Notes

- Queries are starting points. Exclusions and approved-tool lists are environment-specific.
- Hunts and dashboards surface activity for human review. They don't alert or take action on their own.
- Tuning is most likely required for each environment, don't expect for this to work 100% out the box.