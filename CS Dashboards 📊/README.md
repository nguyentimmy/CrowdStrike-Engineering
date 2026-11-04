# 📊 CS Dashboards

Falcon dashboards, split by purpose. Each dashboard doc covers why it exists, its parameters and time range, the CQL behind every widget with the chart type to use, and how to work it.

---

## 🛡️ Endpoint Security

Checks the protection itself. A silent sensor, a noisy rule, or a policy left in detect-only mode creates a quiet gap that nothing alerts on.

| Dashboard | What it does |
| --- | --- |
| 🛡️ [Endpoint Defense Posture](<Endpoint Security/EndpointDefensePosture.md>) | All-in-one view: sensor health, detection trends and timeline, custom IOA/IOC health, and prevention coverage |
| 🩺 [Sensor Health Telemetry](<Endpoint Security/SensorHealthTelemetry.md>) | Who's reporting, who's gone silent, who's flapping, and what's out of date |

---

## 🔎 Security Operations

Daily SOC work: hunting for what alerts miss, investigating compromised hosts, and triaging detections.

| Dashboard | What it does |
| --- | --- |
| 🔎 [Hunt & Response](<Security Operations/Hunt&Response.md>) | Hunt mode sweeps the fleet for undetected activity. Response mode audits a compromised host and feeds the IR report |
| 🚨 [Triage Detection](<Security Operations/TriageDetection.md>) | Detection timeline, host attack path, multi-tactic hosts, and tuning KPIs |

---

## 🔄 How they work together

1. **Hunt** for leads with Hunt & Response in hunt mode.
2. **Triage** detections with Triage Detection.
3. **Investigate** a compromised host with Hunt & Response in response mode, and export the results for the IR report.
4. **Check posture** weekly with Endpoint Defense Posture and Sensor Health Telemetry.
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