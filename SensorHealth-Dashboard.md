# 🩺 Sensor Health & Coverage

CrowdStrike Falcon Next-Gen SIEM dashboard that answers one question: **is the sensor actually running everywhere it should be, and is it healthy?**

---

## 🎯 Why this exists

An endpoint without a working sensor is a blind spot. Detections and hunts only cover hosts that are reporting, so coverage gaps quietly weaken everything else.

This dashboard shows fleet coverage at a glance, then helps you work the gaps: silent hosts, outdated sensors, and hosts that keep dropping off.

> 💡 Coverage is only meaningful against a baseline. The sensor can tell you who is reporting, but not who *should* be. Compare against your AD, Intune, or CMDB host list (see Next steps).

---

## 🗺️ Layout

| Row | Widgets | Type |
| --- | --- | --- |
| **Top** | Active hosts, Silent 3+ days, New sensors (7d) | Single values |
| **Trend** | Hosts reporting over time | Time chart |
| **Breakdown** | Sensor versions, OS, Workstation vs server | Pie / bar charts |
| **Gaps** | Silent-host aging, Stale hosts list | Bar chart + table |
| **Stability** | Reconnect-heavy hosts | Table |

---

## 🎛️ Parameters and time range

| Setting | Use |
| --- | --- |
| `?Hostname` | Filter to one host. Default `*` for the whole fleet |
| Time range | Set the dashboard to **30 days**. The silent-host widgets need a long window to see who went quiet |

> ⚠️ Sensor widgets use raw sensor events (`SensorHeartbeat`, `AgentOnline`), which carry `ComputerName` and `aid`, plus the `aid_master_main.csv` lookup. These were confirmed working in your tenant.

---

## 🧪 Widgets (CQL)

### 1. 🟢 Active Hosts (24h)

*Single value.* Hosts that checked in during the last day.

```
#event_simpleName=SensorHeartbeat
| ComputerName=?Hostname
| now(as=NowMs)
| eval(AgeMs = NowMs - @timestamp)
| test(AgeMs < 86400000)
| count(aid, distinct=true, as=ActiveHosts)
```

### 2. 🔴 Silent 3+ Days

*Single value.* Hosts seen in the window but not for at least 3 days.

```
#event_simpleName=SensorHeartbeat
| ComputerName=?Hostname
| groupBy([aid], function=max(@timestamp, as=LastSeen))
| now(as=NowMs)
| eval(SilentMs = NowMs - LastSeen)
| test(SilentMs > 259200000)
| count(aid, as=SilentHosts)
```

### 3. 🆕 New Sensors (7d)

*Single value.* Hosts first seen this week. A spike is usually a rollout. An unexpected spike deserves a look.

```
#event_simpleName=SensorHeartbeat
| ComputerName=?Hostname
| groupBy([aid], function=min(@timestamp, as=FirstSeen))
| now(as=NowMs)
| eval(AgeMs = NowMs - FirstSeen)
| test(AgeMs < 604800000)
| count(aid, as=NewSensors)
```

### 4. 📈 Hosts Reporting Over Time

*Time chart (line).* A drop here is an outage or a failed deployment. A slow decline is hosts quietly falling off.

```
#event_simpleName=SensorHeartbeat
| ComputerName=?Hostname
| timeChart(span=1d, function=count(aid, distinct=true, as=HostsReporting))
```

### 5. 🧬 Sensor Version Distribution

*Pie or bar chart.* Shows how far the fleet is from one standard version. Small slices are the hosts to chase.

```
#event_simpleName=SensorHeartbeat
| ComputerName=?Hostname
| groupBy([aid], function=[])
| match(file="aid_master_main.csv", field=[aid], include=[AgentVersion], strict=false)
| groupBy([AgentVersion], function=count(aid, as=Hosts))
| sort(Hosts, order=desc)
```

### 6. 🪟 OS Distribution

*Bar chart.* Spots unsupported or legacy operating systems that are also coverage risks.

```
#event_simpleName=SensorHeartbeat
| ComputerName=?Hostname
| groupBy([aid], function=[])
| match(file="aid_master_main.csv", field=[aid], include=[Version], strict=false)
| groupBy([Version], function=count(aid, as=Hosts))
| sort(Hosts, order=desc)
```

### 7. 🖥️ Workstations vs Servers vs DCs

*Pie chart.* Coverage gaps on servers and domain controllers matter more than on laptops.

```
#event_simpleName=SensorHeartbeat
| ComputerName=?Hostname
| groupBy([aid], function=[])
| match(file="aid_master_main.csv", field=[aid], include=[ProductType], strict=false)
| case {
    ProductType = "1" | HostType := "Workstation";
    ProductType = "2" | HostType := "Domain Controller";
    ProductType = "3" | HostType := "Server";
    * | HostType := "Unknown"}
| groupBy([HostType], function=count(aid, as=Hosts))
```

### 8. ⏳ Silent-Host Aging

*Bar chart.* Buckets silent hosts by how long they've been quiet. Hosts quiet for a day are usually laptops. Hosts quiet for weeks are the real gaps.

```
#event_simpleName=SensorHeartbeat
| ComputerName=?Hostname
| groupBy([aid], function=max(@timestamp, as=LastSeen))
| now(as=NowMs)
| eval(DaysSilent = (NowMs - LastSeen) / 86400000)
| case {
    DaysSilent < 1  | Bucket := "0-1 days";
    DaysSilent < 3  | Bucket := "1-3 days";
    DaysSilent < 7  | Bucket := "3-7 days";
    DaysSilent < 14 | Bucket := "7-14 days";
    * | Bucket := "14+ days"}
| groupBy([Bucket], function=count(aid, as=Hosts))
```

### 9. 📋 Stale Hosts List

*Table.* The work queue. Oldest silence first.

```
#event_simpleName=SensorHeartbeat
| ComputerName=?Hostname
| groupBy([aid, ComputerName], function=max(@timestamp, as=LastSeen))
| now(as=NowMs)
| eval(DaysSilent = (NowMs - LastSeen) / 86400000)
| test(DaysSilent >= 3)
| format("%.0f", field=[DaysSilent], as=DaysSilent)
| match(file="aid_master_main.csv", field=[aid], include=[AgentVersion, Version, MachineDomain, OU], strict=false)
| LastSeen := formatTime("%Y-%m-%d %H:%M", field=LastSeen)
| table([ComputerName, DaysSilent, LastSeen, AgentVersion, Version, MachineDomain, OU], limit=200)
| sort(DaysSilent, order=desc)
```

### 10. 🔁 Reconnect-Heavy Hosts

*Table.* Hosts that keep coming back online. Usually a flaky network, proxy or sleep issue, or a sensor restarting.

```
#event_simpleName=AgentOnline
| ComputerName=?Hostname
| groupBy([aid, ComputerName], function=[count(as=Reconnects), max(@timestamp, as=LastOnline)])
| LastOnline := formatTime("%Y-%m-%d %H:%M", field=LastOnline)
| sort(Reconnects, order=desc, limit=50)
```

---

## 🚀 How to use it

1. Check the top row first: active hosts, silent hosts, new sensors.
2. Look at the trend. A sudden drop means an outage or failed rollout. A slow decline means hosts falling off.
3. Use the version and OS charts to find the outliers and plan upgrades.
4. Work the **Stale Hosts** list, oldest first. Decide for each: decommissioned, powered off, or a broken sensor.
5. For broken sensors, check the usual causes: agent-to-console connectivity (DNS, proxy, firewall), a stopped service, or a failed install.
6. Check **Reconnect-Heavy Hosts** for networking or proxy problems.

> 💡 Always separate "gone" from "broken." Decommissioned hosts should be cleaned out of Falcon so they don't inflate the silent count.

---

## 🔭 Next steps

- **Coverage against a baseline.** Upload your AD or Intune host list as a lookup file and compare it with reporting hosts to get a true coverage % and a list of hosts that have no sensor at all.
- **Reduced functionality mode.** Add a widget if your tenant exposes RFM state in its events.
- **Alerting.** Turn "silent 3+ days" into a scheduled search so it notifies you instead of waiting for someone to look.

---

## 📌 Notes

- Silent hosts are not always unhealthy. Laptops, travel, and PTO all create gaps. Judge by pattern, not by a single host.
- The version, OS, and host-type widgets depend on `aid_master_main.csv`. If those columns differ in your tenant, adjust the `include=` lists.
- Short windows hide silent hosts. Keep the dashboard at 30 days or more.