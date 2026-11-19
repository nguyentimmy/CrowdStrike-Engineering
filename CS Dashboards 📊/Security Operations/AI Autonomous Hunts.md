# 🤖 AI & Autonomous Threats (CQL)

A CrowdStrike Falcon Next-Gen SIEM dashboard that tracks LLM API usage and AI-driven attack activity using Falcon sensor telemetry. It covers which devices and processes reach LLM APIs, which hosts combine LLM access with offensive tooling, where AI agent frameworks or local models are installed, and machine-speed scanning, logon spraying and discovery.

> ⚠️ **Disclaimer:** This dashboard provides visibility for hunting and triage. It does not replace alert triage. Detections and incidents should still be investigated for deeper analysis.

---

## 🗂️ Widgets

| # | Widget | Type | Purpose |
|---|---|---|---|
| 1 | 📊 Overview | Single value (x4) | LLM lookups, devices using LLMs, offensive tool runs, agent hosts |
| 2 | 📈 LLM Lookups Over Time | Time chart | Usage trend by provider |
| 3 | 🥧 LLM Lookups by Provider | Pie | Which AI providers are in use |
| 4 | 🏆 Top LLM Callers | Table | Every process resolving LLM APIs, sanctioned vs. unsanctioned |
| 5 | ⚠️ Unsanctioned LLM Activity | Table | Scripts, CLIs and unknown binaries reaching LLM APIs |
| 6 | 🤖 LLM-Driven Offensive Agent | Table | Hosts with LLM lookups **and** offensive tooling |
| 7 | 🔎 Recon Toolchain Burst | Table | 3+ offensive tools from one parent within an hour |
| 8 | 🧩 AI Agent Framework Activity | Table | Installs of agent frameworks and offensive AI tools |
| 9 | 🖥️ Local LLM Runtimes | Table | Ollama, LM Studio and llama.cpp running on hosts |
| 10 | 🌐 Inbound Scan & Sweep Bursts | Table | One source hitting many ports or hosts within 10 minutes |
| 11 | 🔨 Machine-Speed Logon Failures | Table | Brute force and spraying, plus any later success |
| 12 | ⚡ Machine-Speed Discovery | Table | 8+ distinct discovery commands from one parent within a minute |

---

## 📊 1. Overview

**Widget:** Single value, one per query

**🤖 LLM API Lookups**
```
#event_simpleName=DnsRequest
| ComputerName=?Hostname
| DomainName=/(^|\.)(api\.anthropic\.com|api\.openai\.com|openai\.azure\.com|generativelanguage\.googleapis\.com|aiplatform\.googleapis\.com|api\.mistral\.ai|api\.groq\.com|openrouter\.ai|api\.together\.xyz|api\.deepseek\.com|api\.x\.ai|api\.cohere\.(com|ai)|api\.perplexity\.ai|bedrock-runtime\..+\.amazonaws\.com)$/i
| count(as="LLM API Lookups")
```

**💻 Devices Using LLMs**
```
#event_simpleName=DnsRequest
| ComputerName=?Hostname
| DomainName=/(^|\.)(api\.anthropic\.com|api\.openai\.com|openai\.azure\.com|generativelanguage\.googleapis\.com|aiplatform\.googleapis\.com|api\.mistral\.ai|api\.groq\.com|openrouter\.ai|api\.together\.xyz|api\.deepseek\.com|api\.x\.ai|api\.cohere\.(com|ai)|api\.perplexity\.ai|bedrock-runtime\..+\.amazonaws\.com)$/i
| count(aid, distinct=true, as="Devices Using LLMs")
```

**🔎 Offensive Tool Runs**
```
#event_simpleName=ProcessRollup2
| ComputerName=?Hostname
| (FileName=/^(httpx|subfinder|katana|ffuf|nuclei|naabu|amass|gobuster|dnsx|httprobe|nmap|masscan|sqlmap)(\.exe)?$/i or (FileName=/^python/i and CommandLine=/sqlmap/i))
| count(as="Offensive Tool Runs")
```

**🚨 Agent Hosts**
```
(#event_simpleName=DnsRequest DomainName=/(^|\.)(api\.anthropic\.com|api\.openai\.com|openai\.azure\.com|generativelanguage\.googleapis\.com|aiplatform\.googleapis\.com|api\.mistral\.ai|api\.groq\.com|openrouter\.ai|api\.together\.xyz|api\.deepseek\.com|api\.x\.ai|api\.cohere\.(com|ai)|api\.perplexity\.ai|bedrock-runtime\..+\.amazonaws\.com)$/i)
  or (#event_simpleName=ProcessRollup2 (FileName=/^(httpx|subfinder|katana|ffuf|nuclei|naabu|amass|gobuster|dnsx|httprobe|nmap|masscan|sqlmap)(\.exe)?$/i or (FileName=/^python/i and CommandLine=/sqlmap/i)))
| ComputerName=?Hostname
| groupBy([aid], function=[count(field=DomainName, as=LLMLookups), count(field=FileName, as=ToolRuns)])
| LLMLookups > 0
| ToolRuns > 0
| count(as="Agent Hosts")
```

---

## 📈 2. LLM Lookups Over Time

**Widget:** Time chart

```
#event_simpleName=DnsRequest
| ComputerName=?Hostname
| DomainName=/(^|\.)(api\.anthropic\.com|api\.openai\.com|openai\.azure\.com|generativelanguage\.googleapis\.com|aiplatform\.googleapis\.com|api\.mistral\.ai|api\.groq\.com|openrouter\.ai|api\.together\.xyz|api\.deepseek\.com|api\.x\.ai|api\.cohere\.(com|ai)|api\.perplexity\.ai|bedrock-runtime\..+\.amazonaws\.com)$/i
| case {
    DomainName=/anthropic/i | Provider := "Anthropic";
    DomainName=/openai\.azure/i | Provider := "Azure OpenAI";
    DomainName=/openai/i | Provider := "OpenAI";
    DomainName=/googleapis/i | Provider := "Google";
    DomainName=/mistral/i | Provider := "Mistral";
    DomainName=/groq/i | Provider := "Groq";
    DomainName=/openrouter/i | Provider := "OpenRouter";
    DomainName=/together/i | Provider := "Together";
    DomainName=/deepseek/i | Provider := "DeepSeek";
    DomainName=/api\.x\.ai/i | Provider := "xAI";
    DomainName=/cohere/i | Provider := "Cohere";
    DomainName=/perplexity/i | Provider := "Perplexity";
    DomainName=/bedrock/i | Provider := "AWS Bedrock";
    * | Provider := "Other" }
| timeChart(series=Provider, span=1h)
```

---

## 🥧 3. LLM Lookups by Provider

**Widget:** Pie chart

```
#event_simpleName=DnsRequest
| ComputerName=?Hostname
| DomainName=/(^|\.)(api\.anthropic\.com|api\.openai\.com|openai\.azure\.com|generativelanguage\.googleapis\.com|aiplatform\.googleapis\.com|api\.mistral\.ai|api\.groq\.com|openrouter\.ai|api\.together\.xyz|api\.deepseek\.com|api\.x\.ai|api\.cohere\.(com|ai)|api\.perplexity\.ai|bedrock-runtime\..+\.amazonaws\.com)$/i
| case {
    DomainName=/anthropic/i | Provider := "Anthropic";
    DomainName=/openai\.azure/i | Provider := "Azure OpenAI";
    DomainName=/openai/i | Provider := "OpenAI";
    DomainName=/googleapis/i | Provider := "Google";
    DomainName=/mistral/i | Provider := "Mistral";
    DomainName=/groq/i | Provider := "Groq";
    DomainName=/openrouter/i | Provider := "OpenRouter";
    DomainName=/together/i | Provider := "Together";
    DomainName=/deepseek/i | Provider := "DeepSeek";
    DomainName=/api\.x\.ai/i | Provider := "xAI";
    DomainName=/cohere/i | Provider := "Cohere";
    DomainName=/perplexity/i | Provider := "Perplexity";
    DomainName=/bedrock/i | Provider := "AWS Bedrock";
    * | Provider := "Other" }
| groupBy([Provider], function=count(as=Lookups))
| sort(Lookups, order=desc)
```

---

## 🏆 4. Top LLM Callers

**Widget:** Table

Joins each DNS lookup to the process that made it (`ContextProcessId` → `TargetProcessId`).

```
#event_simpleName=DnsRequest
| ComputerName=?Hostname
| DomainName=/(^|\.)(api\.anthropic\.com|api\.openai\.com|openai\.azure\.com|generativelanguage\.googleapis\.com|aiplatform\.googleapis\.com|api\.mistral\.ai|api\.groq\.com|openrouter\.ai|api\.together\.xyz|api\.deepseek\.com|api\.x\.ai|api\.cohere\.(com|ai)|api\.perplexity\.ai|bedrock-runtime\..+\.amazonaws\.com)$/i
| join({#event_simpleName=ProcessRollup2}, field=[aid, ContextProcessId], key=[aid, TargetProcessId], include=[FileName, CommandLine, UserName], mode=left)
| default(field=[FileName, UserName], value="unknown")
| case {
    FileName=/^(msedge|chrome|firefox|brave|msedgewebview2|claude|chatgpt|code|ms-teams|teams)\.exe$/i | Status := "✅ Sanctioned";
    * | Status := "⚠️ Unsanctioned" }
| groupBy([Status, FileName], function=[
    count(as=Lookups),
    count(aid, distinct=true, as=Devices),
    collect([DomainName, ComputerName, UserName], limit=5),
    min(@timestamp, as=FirstSeen),
    max(@timestamp, as=LastSeen)])
| FirstSeen := formatTime("%Y-%m-%d %H:%M:%S", field=FirstSeen)
| LastSeen := formatTime("%Y-%m-%d %H:%M:%S", field=LastSeen)
| sort([Status, Lookups], order=[desc, desc], limit=200)
| table([Status, FileName, Lookups, Devices, DomainName, ComputerName, UserName, FirstSeen, LastSeen])
```

---

## ⚠️ 5. Unsanctioned LLM Activity

**Widget:** Table

Scripting runtimes and CLI tools reaching LLM APIs rank highest, because that's how agents and malware use them.

```
#event_simpleName=DnsRequest
| ComputerName=?Hostname
| DomainName=/(^|\.)(api\.anthropic\.com|api\.openai\.com|openai\.azure\.com|generativelanguage\.googleapis\.com|aiplatform\.googleapis\.com|api\.mistral\.ai|api\.groq\.com|openrouter\.ai|api\.together\.xyz|api\.deepseek\.com|api\.x\.ai|api\.cohere\.(com|ai)|api\.perplexity\.ai|bedrock-runtime\..+\.amazonaws\.com)$/i
| join({#event_simpleName=ProcessRollup2}, field=[aid, ContextProcessId], key=[aid, TargetProcessId], include=[FileName, CommandLine, UserName], mode=left)
| default(field=[FileName, CommandLine, UserName], value="unknown")
| not FileName=/^(msedge|chrome|firefox|brave|msedgewebview2|claude|chatgpt|code|ms-teams|teams)\.exe$/i
| groupBy([ComputerName, UserName, FileName, CommandLine], function=[
    count(as=Lookups),
    collect([DomainName], limit=5),
    min(@timestamp, as=FirstSeen),
    max(@timestamp, as=LastSeen)])
| case {
    FileName=/^(python|python3|python\.exe|pythonw\.exe|node|node\.exe|go|curl|curl\.exe|wget|powershell\.exe|pwsh|pwsh\.exe|bash|sh|docker|containerd-shim)$/i | eval(SevRank = 2) | Severity := "🟠 High";
    * | eval(SevRank = 3) | Severity := "🟡 Medium" }
| FirstSeen := formatTime("%Y-%m-%d %H:%M:%S", field=FirstSeen)
| LastSeen := formatTime("%Y-%m-%d %H:%M:%S", field=LastSeen)
| sort([SevRank, Lookups], order=[asc, desc], limit=200)
| table([FirstSeen, Severity, Lookups, ComputerName, UserName, FileName, DomainName, CommandLine, LastSeen])
```

---

## 🤖 6. LLM-Driven Offensive Agent

**Widget:** Table

The main signature of an autonomous attack tool: one host resolves LLM APIs **and** runs offensive tooling. Legitimate activity rarely does both.

```
(#event_simpleName=DnsRequest DomainName=/(^|\.)(api\.anthropic\.com|api\.openai\.com|openai\.azure\.com|generativelanguage\.googleapis\.com|aiplatform\.googleapis\.com|api\.mistral\.ai|api\.groq\.com|openrouter\.ai|api\.together\.xyz|api\.deepseek\.com|api\.x\.ai|api\.cohere\.(com|ai)|api\.perplexity\.ai|bedrock-runtime\..+\.amazonaws\.com)$/i)
  or (#event_simpleName=ProcessRollup2 (FileName=/^(httpx|subfinder|katana|ffuf|nuclei|naabu|amass|gobuster|dnsx|httprobe|nmap|masscan|sqlmap)(\.exe)?$/i or (FileName=/^python/i and CommandLine=/sqlmap/i)))
| ComputerName=?Hostname
| groupBy([aid, ComputerName], function=[
    count(field=DomainName, as=LLMLookups),
    count(field=FileName, as=ToolRuns),
    count(field=FileName, distinct=true, as=DistinctTools),
    collect([DomainName, FileName], limit=10),
    collect([CommandLine], limit=8),
    min(@timestamp, as=FirstSeen),
    max(@timestamp, as=LastSeen)])
| LLMLookups > 0
| ToolRuns > 0
| case {
    DistinctTools >= 3 | eval(SevRank = 1) | Severity := "🔴 Critical";
    * | eval(SevRank = 2) | Severity := "🟠 High" }
| Signal := "🤖 LLM-Driven Offensive Agent"
| FirstSeen := formatTime("%Y-%m-%d %H:%M:%S", field=FirstSeen)
| LastSeen := formatTime("%Y-%m-%d %H:%M:%S", field=LastSeen)
| sort([SevRank, ToolRuns], order=[asc, desc], limit=200)
| table([FirstSeen, Severity, Signal, ComputerName, LLMLookups, DomainName, ToolRuns, DistinctTools, FileName, CommandLine, LastSeen])
```

---

## 🔎 7. Recon Toolchain Burst

**Widget:** Table

Agents chain recon tools quickly from a single parent process. This catches the burst even when the LLM traffic isn't visible.

```
#event_simpleName=ProcessRollup2
| ComputerName=?Hostname
| (FileName=/^(httpx|subfinder|katana|ffuf|nuclei|naabu|amass|gobuster|dnsx|httprobe|nmap|masscan|sqlmap)(\.exe)?$/i or (FileName=/^python/i and CommandLine=/sqlmap/i))
| default(field=[UserName, ParentBaseFileName], value="-")
| Hour := formatTime("%Y-%m-%d %H:00", field=@timestamp)
| groupBy([ComputerName, UserName, ParentBaseFileName, Hour], function=[
    count(FileName, distinct=true, as=DistinctTools),
    count(as=Runs),
    collect([FileName], limit=20),
    collect([CommandLine], limit=8),
    min(@timestamp, as=FirstSeen),
    max(@timestamp, as=LastSeen)])
| DistinctTools >= 3
| case {
    DistinctTools >= 5 | eval(SevRank = 1) | Severity := "🔴 Critical";
    * | eval(SevRank = 2) | Severity := "🟠 High" }
| FirstSeen := formatTime("%Y-%m-%d %H:%M:%S", field=FirstSeen)
| LastSeen := formatTime("%Y-%m-%d %H:%M:%S", field=LastSeen)
| sort([SevRank, DistinctTools], order=[asc, desc], limit=200)
| table([FirstSeen, Severity, DistinctTools, FileName, Runs, ComputerName, UserName, ParentBaseFileName, CommandLine, LastSeen])
```

---

## 🧩 8. AI Agent Framework Activity

**Widget:** Table

Installs of AI agent frameworks and offensive AI tools through pip, npm, git, docker or go. Known offensive AI tools rank highest.

```
#event_simpleName=ProcessRollup2
| ComputerName=?Hostname
| CommandLine=/(pip3? install|uv (add|pip)|npm (install|i )|git clone|docker (pull|run)|go (install|get))/i
| CommandLine=/(artex|pentestgpt|pentagi|hackingbuddygpt|hexstrike|villager|langchain|langgraph|autogen|crewai|open-interpreter|browser-use|litellm|anthropic|openai|ollama)/i
| default(field=[UserName, ParentBaseFileName], value="-")
| case {
    CommandLine=/(artex|pentestgpt|pentagi|hackingbuddygpt|hexstrike|villager)/i | eval(SevRank = 1) | Severity := "🔴 Critical" | Signal := "☠️ Offensive AI Tool";
    * | eval(SevRank = 4) | Severity := "🔵 Low" | Signal := "🧩 Agent Framework" }
| groupBy([SevRank, Severity, Signal, ComputerName, UserName, FileName, CommandLine, ParentBaseFileName], function=[
    count(as=Hits),
    min(@timestamp, as=FirstSeen),
    max(@timestamp, as=LastSeen)])
| FirstSeen := formatTime("%Y-%m-%d %H:%M:%S", field=FirstSeen)
| LastSeen := formatTime("%Y-%m-%d %H:%M:%S", field=LastSeen)
| sort([SevRank, LastSeen], order=[asc, desc], limit=200)
| table([FirstSeen, Severity, Signal, Hits, ComputerName, UserName, FileName, CommandLine, ParentBaseFileName, LastSeen])
```

---

## 🖥️ 9. Local LLM Runtimes

**Widget:** Table

Local models make no external API calls, so they won't appear in widgets 2 to 6. This shows where they're running.

```
#event_simpleName=ProcessRollup2
| ComputerName=?Hostname
| FileName=/^(ollama|ollama app|llama-server|llama-cli|lms|lm studio|vllm|koboldcpp)(\.exe)?$/i
| default(field=[UserName], value="-")
| groupBy([ComputerName, FileName], function=[
    count(as=Launches),
    collect([UserName], limit=5),
    collect([CommandLine], limit=5),
    min(@timestamp, as=FirstSeen),
    max(@timestamp, as=LastSeen)])
| FirstSeen := formatTime("%Y-%m-%d %H:%M:%S", field=FirstSeen)
| LastSeen := formatTime("%Y-%m-%d %H:%M:%S", field=LastSeen)
| sort(LastSeen, order=desc, limit=200)
| table([FirstSeen, ComputerName, FileName, Launches, UserName, CommandLine, LastSeen])
```

---

## 🌐 10. Inbound Scan & Sweep Bursts

**Widget:** Table

Accepted inbound connections grouped by source in 10-minute windows. Internal sources are kept, because an internal host scanning others usually means lateral movement.

```
#event_simpleName=NetworkReceiveAcceptIP4
| ComputerName=?Hostname
| RemoteAddressIP4=*
| not RemoteAddressIP4=/^(127\.|0\.0\.0\.0)/
| Window := formatTime("%Y-%m-%d %H:%M", field=@timestamp)
| replace(regex="[0-9]$", with="0", field=Window, as=Window)
| groupBy([RemoteAddressIP4, Window], function=[
    count(LocalPort, distinct=true, as=Ports),
    count(ComputerName, distinct=true, as=Targets),
    count(as=Connections),
    collect([LocalPort, ComputerName], limit=15),
    min(@timestamp, as=FirstSeen),
    max(@timestamp, as=LastSeen)])
| (Ports >= 10 or Targets >= 5 or Connections >= 200)
| groupBy([RemoteAddressIP4], function=[
    count(as=Bursts),
    max(Ports, as=MaxPorts),
    max(Targets, as=MaxTargets),
    sum(Connections, as=Connections),
    collect([LocalPort, ComputerName], limit=20),
    min(FirstSeen, as=FirstSeen),
    max(LastSeen, as=LastSeen)])
| case {
    cidr(RemoteAddressIP4, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]) | Source := "🏠 Internal";
    * | Source := "🌍 External" }
| case {
    MaxTargets >= 5 MaxPorts >= 10 | Pattern := "🎯 Sweep + Port Scan";
    MaxTargets >= 5 | Pattern := "🌐 Host Sweep";
    MaxPorts >= 10 | Pattern := "🔎 Port Scan";
    * | Pattern := "⚡ High Volume" }
| case {
    MaxPorts >= 50 | eval(SevRank = 1);
    MaxTargets >= 20 | eval(SevRank = 1);
    MaxTargets >= 5 MaxPorts >= 10 | eval(SevRank = 2);
    Source="🏠 Internal" | eval(SevRank = 2);
    * | eval(SevRank = 3) }
| case {
    SevRank = 1 | Severity := "🔴 Critical";
    SevRank = 2 | Severity := "🟠 High";
    * | Severity := "🟡 Medium" }
| FirstSeen := formatTime("%Y-%m-%d %H:%M:%S", field=FirstSeen)
| LastSeen := formatTime("%Y-%m-%d %H:%M:%S", field=LastSeen)
| sort([SevRank, Connections], order=[asc, desc], limit=200)
| table([FirstSeen, Severity, Pattern, Source, RemoteAddressIP4, Bursts, MaxPorts, MaxTargets, Connections, LocalPort, ComputerName, LastSeen])
```

---

## 🔨 11. Machine-Speed Logon Failures

**Widget:** Table

Failed logons from one source in 10-minute windows. Many accounts means spraying, and many attempts on few accounts means brute force. `Succeeded` flags a source that later logged in successfully, which should be treated as a compromise.

```
#event_simpleName=/^(UserLogonFailed2|UserLogon)$/
| ComputerName=?Hostname
| RemoteAddressIP4=*
| not RemoteAddressIP4=/^(127\.|0\.0\.0\.0)/
| default(field=[UserName, LogonType], value="-")
| case {
    #event_simpleName=UserLogonFailed2 | rename(field=UserName, as=FailUser) | eval(FailTime = @timestamp);
    * | rename(field=UserName, as=OkUser) | eval(OkTime = @timestamp) }
| Window := formatTime("%Y-%m-%d %H:%M", field=@timestamp)
| replace(regex="[0-9]$", with="0", field=Window, as=Window)
| groupBy([RemoteAddressIP4, Window], function=[
    count(field=FailUser, as=Failures),
    count(field=FailUser, distinct=true, as=Users),
    count(field=OkUser, as=Successes),
    collect([FailUser, OkUser, ComputerName, LogonType], limit=10),
    min(FailTime, as=FirstFail),
    max(OkTime, as=LastOk)])
| case {
    Failures >= 20 | eval(IsBurst = 1);
    Users >= 5 | eval(IsBurst = 1);
    * | eval(IsBurst = 0) }
| groupBy([RemoteAddressIP4], function=[
    sum(IsBurst, as=Bursts),
    sum(Failures, as=Failures),
    max(Users, as=MaxUsers),
    sum(Successes, as=Successes),
    collect([FailUser, OkUser, ComputerName, LogonType], limit=15),
    min(FirstFail, as=FirstFail),
    max(LastOk, as=LastOk)])
| Bursts > 0
| case {
    test(LastOk >= FirstFail) | Succeeded := "Yes";
    * | Succeeded := "No" }
| case {
    MaxUsers >= 5 | Pattern := "🧪 Password Spray";
    * | Pattern := "🔨 Brute Force" }
| case {
    cidr(RemoteAddressIP4, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]) | Source := "🏠 Internal";
    * | Source := "🌍 External" }
| case {
    Succeeded="Yes" | eval(SevRank = 1) | Severity := "🔴 Critical";
    Failures >= 100 | eval(SevRank = 2) | Severity := "🟠 High";
    MaxUsers >= 20 | eval(SevRank = 2) | Severity := "🟠 High";
    * | eval(SevRank = 3) | Severity := "🟡 Medium" }
| FirstFail := formatTime("%Y-%m-%d %H:%M:%S", field=FirstFail)
| sort([SevRank, Failures], order=[asc, desc], limit=200)
| table([FirstFail, Severity, Pattern, Source, RemoteAddressIP4, Succeeded, OkUser, Failures, MaxUsers, FailUser, ComputerName, LogonType, Bursts])
```

---

## ⚡ 12. Machine-Speed Discovery

**Widget:** Table

After a foothold, an agent runs discovery commands far faster than a person types. This counts distinct discovery actions per parent process in 1-minute windows and flags 8 or more. Each `net` subcommand (`net user`, `net group`, `net view`) counts as its own action, and `net1` is merged into `net`.

```
#event_simpleName=ProcessRollup2
| ComputerName=?Hostname
| (FileName=/^(whoami|net|net1|nltest|ipconfig|systeminfo|hostname|tasklist|quser|qwinsta|query|arp|route|netstat|nslookup|dsquery|klist|gpresult|cmdkey|getmac|driverquery|wmic)\.exe$/i
    or FileName=/^(whoami|id|uname|hostname|hostnamectl|ifconfig|ip|netstat|ss|ps|w|who|last|groups|env|printenv|lsb_release|arp|route)$/)
| not ParentBaseFileName=/^(MsSense|SenseIR|SenseCncProxy|SenseNdr|MsMpEng|WaAppAgent|WindowsAzureGuestAgent|CollectGuestLogs|IntuneManagementExtension|AgentExecutor|CcmExec|CSFalconService|falcon-sensor|waagent|omsagent|azuremonitoragent|telegraf)(\.exe)?$/i
| default(field=[UserName, ParentBaseFileName, GrandParentBaseFileName], value="-")
| regex("(?i)net1?(?:[.]exe)?[ ]+(?<NetSub>[a-z]+)", field=CommandLine, strict=false)
| default(field=NetSub, value="")
| lower(FileName, as=Cmd)
| replace(regex="[.]exe$", with="", field=Cmd, as=Cmd)
| case {
    Cmd=/^net1?$/ | format("net %s", field=[NetSub], as=Action);
    * | format("%s", field=[Cmd], as=Action) }
| Minute := formatTime("%Y-%m-%d %H:%M", field=@timestamp)
| groupBy([aid, ComputerName, UserName, ParentProcessId, ParentBaseFileName, GrandParentBaseFileName, Minute], function=[
    count(Action, distinct=true, as=DistinctCmds),
    count(as=Execs),
    collect([Action], limit=30),
    collect([CommandLine], limit=15),
    min(@timestamp, as=FirstSeen),
    max(@timestamp, as=LastSeen)])
| DistinctCmds >= 8
| eval(SpanSec = (LastSeen - FirstSeen) / 1000)
| format("%.0f", field=[SpanSec], as=SpanSec)
| case {
    DistinctCmds >= 15 | eval(SevRank = 1);
    DistinctCmds >= 10 ParentBaseFileName=/^(python|python3|pythonw?\.exe|node(\.exe)?|go|powershell\.exe|pwsh(\.exe)?|wscript\.exe|cscript\.exe|mshta\.exe|w3wp\.exe|sqlservr\.exe|java(\.exe)?|php|php-cgi|httpd|nginx|apache2)$/i | eval(SevRank = 1);
    DistinctCmds >= 10 | eval(SevRank = 2);
    ParentBaseFileName=/^(python|python3|pythonw?\.exe|node(\.exe)?|go|powershell\.exe|pwsh(\.exe)?|wscript\.exe|cscript\.exe|mshta\.exe|w3wp\.exe|sqlservr\.exe|java(\.exe)?|php|php-cgi|httpd|nginx|apache2)$/i | eval(SevRank = 2);
    GrandParentBaseFileName=/^(python|python3|pythonw?\.exe|node(\.exe)?|go|powershell\.exe|pwsh(\.exe)?|w3wp\.exe|java(\.exe)?|php|httpd|nginx|apache2)$/i | eval(SevRank = 2);
    * | eval(SevRank = 3) }
| case {
    SevRank = 1 | Severity := "🔴 Critical";
    SevRank = 2 | Severity := "🟠 High";
    * | Severity := "🟡 Medium" }
| Signal := "⚡ Machine-Speed Discovery"
| FirstSeen := formatTime("%Y-%m-%d %H:%M:%S", field=FirstSeen)
| LastSeen := formatTime("%Y-%m-%d %H:%M:%S", field=LastSeen)
| sort([SevRank, DistinctCmds], order=[asc, desc], limit=200)
| table([FirstSeen, Severity, Signal, DistinctCmds, Execs, SpanSec, ComputerName, UserName, ParentBaseFileName, GrandParentBaseFileName, Action, CommandLine, LastSeen])
```
