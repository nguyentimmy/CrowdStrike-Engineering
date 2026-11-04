# 🦅 CrowdStrike Engineering

CrowdStrike Falcon dashboards, widgets, hunting queries, and custom detections, built from real SOC work.

The focus: find the activity alerts miss, check that protection is actually working, and keep triage fast, without adding to alert fatigue.

---

## 🗂️ Repo layout

| Folder | What's inside |
| --- | --- |
| 📊 [CS Dashboards](<CS Dashboards 📊/>) | Falcon dashboards, each documented with the CQL behind every widget |
| ↳ 🛡️ [Endpoint Security](<CS Dashboards 📊/Endpoint Security/>) | Protection health: sensor coverage, detections, custom IOA/IOC health, prevention |
| ↳ 🔎 [Security Operations](<CS Dashboards 📊/Security Operations/>) | Day-to-day SOC work: daily threat hunts and detection triage |
| 🐦‍🔥 [CS Detection](<CS Detection 🐦‍🔥/>) | Custom IOAs and correlation rules, promoted from hunts that proved high-fidelity |

---

## 🎯 Approach

- **Hunting** surfaces noisy and undetected activity as leads for an analyst, not as more alerts.
- **Posture** checks the protection itself: sensors running everywhere, rules tuned, prevention on.
- **Detection** is where proven hunts end up, as custom rules that fire on their own.

---

## ⚙️ Requirements

- Built for **Falcon Next-Gen SIEM / Advanced event search** (CQL).
- Hunts are Windows-focused.
- Event names and fields can differ between tenants, data sources, and licensed modules. Verify on one raw event before saving a widget.

---

## 🧰 CQL notes

Lessons learned while building these, useful for anyone adapting them:

- Detections live in `#repo=detections` as `Event_EppDetectionSummaryEvent`, and use `Hostname` instead of `ComputerName`.
- `case` is its own step: `| case { cond | X := "a"; * | X := "b" }`.
- `now()` is a step too: `| now(as=NowMs)`, then do the math in `eval()`.
- Negate regex with `not Field=/regex/`.
- An optional parameter filter drops events missing that field. Set a default first: `default(field=UserName, value="-")`.
- Empty result? Check the event name and repo first, then remove filter lines one at a time.

---

## 📌 Notes

- Queries are starting points. Exclusions and approved-tool lists are environment-specific.
- Hunts and dashboards surface activity for human review. They don't alert or take action on their own.