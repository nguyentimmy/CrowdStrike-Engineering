# 📊 CS Dashboards

Falcon dashboards, split by purpose. Each dashboard doc covers why it exists, its parameters and time range, the CQL behind every widget with the chart type to use, and how to work it.

---

## 🛡️ Endpoint Security

Checks the protection itself. A silent sensor, a noisy rule, or a policy left in detect-only mode creates a quiet gap that nothing alerts on.

| Dashboard | What it does |
| --- | --- |
| 🛡️ [Endpoint Defense Posture](<Endpoint Security/EndpointDefensePosture-Dashboard.md>) | All-in-one view: sensor health, detection trends and timeline, custom IOA/IOC health, and prevention coverage |
| 🩺 [Sensor Health](<Endpoint Security/SensorHealth-Dashboard.md>) | Who's reporting, who's gone silent, who's flapping, and what's out of date |

---

## 🔎 Security Operations

Daily SOC work: hunting for what alerts miss, and triaging what they catch.

| Dashboard | What it does |
| --- | --- |
| 🔎 [Daily Threat Hunts](<Security Operations/ThreatHuntV2-Dashboard.md>) | 17 daily hunts across execution, evasion, identity, persistence, and lateral movement |
| 🚨 [Triage & Detection KPI](<Security Operations/TriageDetection-Dashboard.md>) | Detection timeline, host attack path, multi-tactic hosts, and tuning trends |
| 🗄️ [Daily Threat Hunts v1 (OG)](<Security Operations/ThreatHunt-Dashboard.md>) | Original 7-hunt pilot, kept for history |

---

## 🔄 How they work together

1. **Hunt** for leads with Daily Threat Hunts.
2. **Triage** detections with Triage & Detection KPI.
3. **Investigate** one host by setting `?Hostname` and reading its attack path.
4. **Check posture** weekly with Endpoint Defense Posture and Sensor Health.
5. **Promote** proven hunts into custom rules in [CS Detection](<../CS Detection 🐦‍🔥/>).

---

## 🎛️ Common parameters

| Parameter | Use |
| --- | --- |
| `?Hostname` | Scope to one host. Default `*` for the whole fleet |
| `?User` | Scope to one account (hunts only). Default `*` |

---

## 📌 Notes

- Sensor widgets need a **30-day** range so silent hosts show up. Triage works best at **7 days**.
- Sensor standard: **N-1** by default, and remediate anything older than **N-2**.
- If a widget returns nothing, the field or event name probably differs in your tenant. Check one raw event.