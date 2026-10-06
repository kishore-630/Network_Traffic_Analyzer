<div align="center">

# 🛰️ Network Traffic Analyzer

### _Read a `.pcap` file — or record one live. Understand the traffic. Catch what does not belong._

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Kali Linux](https://img.shields.io/badge/Kali%20Linux-ready-367bf2?style=for-the-badge&logo=kali-linux&logoColor=white)](https://www.kali.org/)
[![Scapy](https://img.shields.io/badge/Scapy-2.5%2B-blue?style=for-the-badge&logo=python&logoColor=white)](https://scapy.net/)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey?style=for-the-badge)](#-installation)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![No Root](https://img.shields.io/badge/offline%20analysis-no%20root%20needed-brightgreen?style=for-the-badge)](#-installation)

`offline pcap analysis` · `live capture` · `anomaly detection` · `zero cloud calls`

</div>

---

## 📖 What is this?

A beginner-friendly command-line tool that shows beautiful traffic statistics
and flags anything that looks suspicious — using rules you can actually read and
understand.

It works in **two modes**, and both run through the exact same detection engine:

|     | Mode              | What it does                                                                    | Command                         | Needs root?                   |
| --- | ----------------- | ------------------------------------------------------------------------------- | ------------------------------- | ----------------------------- |
| 📁  | **Offline**       | Analyses a `.pcap` / `.pcapng` file you already have on disk                    | `python main.py <file.pcap>`    | ❌ No                         |
| 📡  | **Online (live)** | Records packets straight from a network interface, then analyses them in memory | `python main.py --live -i eth0` | ✅ Yes — plus Npcap / libpcap |

**Offline** is for the capture you already have — a file from a colleague, a
downloaded sample, or last week's incident.

**Online** records traffic as it happens and analyzes it in the same run: point
it at an interface, give it a packet count or a timeout, and it hands you the
same tables, the same findings and the same reports. Every live run is also
written to `pcaps/live_<timestamp>.pcap`, so you can re-analyse it offline later
or open it in Wireshark.

| 🧩                           | 💡 Why it exists                                                                          |
| ---------------------------- | ----------------------------------------------------------------------------------------- |
| 📁 **Offline analysis**      | Re-analyse any capture, any time, with no capture backend and no root                     |
| 📡 **Live capture**          | One command records _and_ analyses — no second tool, no `tcpdump` hand-off                |
| 🔁 **Same engine both ways** | Offline and online runs produce identical findings and reports                            |
| 🧮 **Real statistics**       | Packets, bytes, duration, protocols, top talkers, top ports, DNS domains, TCP flags       |
| 🚨 **8 explainable rules**   | Port scans, SYN floods, volume spikes, odd ports, DNS abuse, ICMP floods, clear-text HTTP |
| 🎯 **Severity grading**      | Every finding is `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` or `INFO` — sorted worst-first       |
| 🎨 **Premium terminal UI**   | Boxed banner, colored tables, ANSI-aware alignment, automatic ASCII fallback              |
| 💾 **Reports you can keep**  | A boxed `.txt` report for humans and a long-format `.csv` for Excel / pandas / SQL        |
| 🔒 **Private**               | No telemetry, no API calls, no uploads. Ever.                                             |

> 💡 **TL;DR** — analyse a file you already have, **or** record one live. Either
> way you get the same tables, the same findings and the same reports.
>
> ```bash
> python main.py pcaps/attack_demo.pcap --full        # 📁 offline
> sudo python main.py --live -i eth0 -c 200 --full   # 📡 online
> ```

---

## ⚡ Quick Start

### 📁 Offline — analyse a capture you already have

```bash
# 1️⃣  Install the dependencies
cd network-traffic-analyzer
pip install -r requirements.txt

# 2️⃣  Run the interactive menu on a capture
python main.py pcaps/sample.pcap

# 3️⃣  Or get the full picture in one shot, no menu, report saved
python main.py pcaps/sample.pcap --full
```

### 📡 Online — record live traffic and analyse it

Live capture needs a capture backend and root rights. Linux and macOS already
have what they need; Windows needs [Npcap](https://npcap.com/dist/) installed
with **WinPcap API support** ticked.

```bash
# See what you can record from (no capture started)
python main.py --list-interfaces

# Record 200 packets from a real interface, then analyse + save
sudo python main.py --live -i eth0 -c 200 --full

# Let it pick the interface for you, and filter to HTTPS only
sudo python main.py --live -c 300 --filter "port 443" --full
```

Run `--live` without `-i` and the tool prints every interface with a number and
waits for you to choose — no typing long interface names, no guessing.

<details>
<summary>🐧 Kali Linux? Use these commands instead</summary>

```bash
# Kali ships pip in "externally managed" mode, so either use a virtualenv...
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# ...or override the guard (fine for a throwaway analysis VM):
pip install --break-system-packages -r requirements.txt

# libpcap and tcpdump are already installed on Kali, so live capture and
# every capture command below work out of the box.
```

</details>

---

## 🎁 Bundled demo captures

Two demo files sit in `pcaps/` ready to use:

| File                  | Packets |    Size | What it contains                                                                                                           |
| :-------------------- | ------: | ------: | :------------------------------------------------------------------------------------------------------------------------- |
| 📄 `sample.pcap`      |      10 |   618 B | Small, harmless packets — perfect for a first run                                                                          |
| 🎬 `attack_demo.pcap` |     365 | 21.7 KB | **Deliberately triggers every rule** (port scan, SYN flood, high volume, DNS flood, odd port, ICMP flood, clear-text HTTP) |

```bash
python main.py pcaps/attack_demo.pcap --full   # see the tool light up red
```

> ⚠️ **Note on `.gitignore`:** `pcaps/*.pcap` is ignored on purpose, because a
> capture file can be large and contains real (sensitive) traffic. The two demo
> files above are therefore **not committed to the repository** — they exist in
> a local working copy. On a fresh clone, bring your own capture, record one
> with `--live`, or download a sample from the
> [Wireshark SampleCaptures](https://wiki.wireshark.org/SampleCaptures) page.

---

## ✨ Features

|     | Feature                | What you get                                                                                    |
| :-- | :--------------------- | :---------------------------------------------------------------------------------------------- |
| 📁  | **Offline mode**       | Analyse any `.pcap` / `.pcapng` — no capture backend, no root                                   |
| 📡  | **Online mode**        | `--live` records from an interface and analyses it in the same run                              |
| 🎚️  | **Interface picker**   | `--list-interfaces` and a numbered menu, so you never type a device path                        |
| 🔎  | **Capture filters**    | `--filter "port 443"` — tcpdump/BPF syntax, applied while recording                             |
| ⏹️  | **Bounded by design**  | `--count` and `--timeout` stop the capture by themselves; `Ctrl+C` also works                   |
| 📊  | **Traffic overview**   | Total packets, total bytes, average frame size, capture duration, unique source/destination IPs |
| 🌐  | **Protocol breakdown** | TCP / UDP / ICMP / Other counts with a share of the total                                       |
| 🗣️  | **Top talkers**        | Top 5 source IPs, destination IPs, source ports and destination ports (with service names)      |
| 🔍  | **DNS insight**        | How many queries, which domains were asked for most, and which browsing service they belong to  |
| 🚩  | **TCP flags**          | SYN / ACK / SYN-ACK / RST / FIN / PSH counters                                                  |
| 🕵️  | **Anomaly detection**  | 8 rules, each graded by severity, sorted worst-first                                            |
| 🖥️  | **Interactive menu**   | Re-display any section, save reports, or switch files without restarting                        |
| ⚡  | **One-shot CLI modes** | `--full`, `--stats-only`, `--anomalies-only`, `--no-save` — perfect for scripts                 |
| 💾  | **Report generation**  | Boxed `.txt` report + long-format `.csv`, both timestamped                                      |
| 🪟  | **Cross-platform**     | Linux, macOS and Windows — with a graceful ASCII fallback on old consoles                       |
| 🧠  | **No black boxes**     | Every threshold lives in `config.py`, every rule is a short readable function                   |
| 🔒  | **Private**            | No telemetry, no API calls, no uploads. Ever.                                                   |

---

## 🗂️ Project Structure

```text
network-traffic-analyzer/
│
├── 📄 README.md               ← you are here
├── 📜 LICENSE                 ← MIT
├── 📦 requirements.txt        ← scapy, colorama, tabulate (+ Npcap notes)
├── ⚙️  config.py               ← ALL thresholds + live defaults live here
│
├── 🚀 main.py                  ← CLI entry point: parse args, orchestrate, exit
│
├── 🧠 analyzer/
│   ├── 📘 __init__.py          ← package docstring + version
│   ├── 🛠️  utils.py             ← load captures, format bytes/duration, text width
│   ├── 📡 live.py              ← live capture: interfaces, sniff(), save, errors
│   ├── 📊 stats.py             ← one pass over the packets → all statistics
│   ├── 🚨 anomalies.py         ← 8 rules → severity-graded findings
│   ├── 🎨 ui.py                ← every color, glyph and ANSI-aware table
│   └── 💾 report.py            ← .txt report + .csv summary writers
│
├── 📁 pcaps/                   ← captures go here
│   ├── sample.pcap             ← tiny demo capture (10 packets)
│   ├── attack_demo.pcap        ← demo capture that triggers every rule
│   └── live_<timestamp>.pcap   ← written by --live
│
├── 📁 reports/                 ← generated: report_<timestamp>.txt
└── 📁 output/                  ← generated: summary_<timestamp>.csv
```

### 🧭 Which file do I edit?

| I want to…                                                   | Open                                                          |
| :----------------------------------------------------------- | :------------------------------------------------------------ |
| Change how suspicious something must be before it is flagged | ⚙️ `config.py`                                                |
| Change how long / how many packets a live capture records    | ⚙️ `config.py` (`LIVE_DEFAULT_COUNT`, `LIVE_DEFAULT_TIMEOUT`) |
| Add a new detection rule                                     | 🚨 `analyzer/anomalies.py`                                    |
| Tweak live capture behaviour (filters, progress, errors)     | 📡 `analyzer/live.py`                                         |
| Add a new statistic (e.g. count ARP packets)                 | 📊 `analyzer/stats.py`                                        |
| Change colors, the banner or the tables                      | 🎨 `analyzer/ui.py`                                           |
| Change what the saved report contains                        | 💾 `analyzer/report.py`                                       |

---

## 🔧 Installation

### 📋 Requirements

| Requirement        | Version        | Needed for           | Note                                                                       |
| :----------------- | :------------- | :------------------- | :------------------------------------------------------------------------- |
| 🐍 Python          | 3.9 or newer   | both modes           | `python3 --version`                                                        |
| 🧬 Scapy           | 2.5+           | both modes           | reads `.pcap` / `.pcapng`, records live                                    |
| 🎨 colorama        | 0.4.6+         | both modes           | colors that also work on Windows                                           |
| 📑 tabulate        | 0.9+           | both modes           | aligned tables inside the reports                                          |
| 🧬 libpcap / Npcap | system package | **online mode only** | pre-installed on Kali; on Windows install [Npcap](https://npcap.com/dist/) |

### ⬇️ Install

```bash
# 1. Clone or copy the project
cd network-traffic-analyzer

# 2. Create a virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate          # Windows PowerShell:  venv\Scripts\Activate.ps1

# 3. Install the dependencies
pip install -r requirements.txt

# 4. Sanity check — you should see the version
python main.py --version
```

<details>
<summary>🪟 Windows (PowerShell)</summary>

```powershell
cd network-traffic-analyzer
python -m venv venv
venv\Scripts\Activate.ps1
pip install -r requirements.txt
python main.py --version
```

**Online mode on Windows** needs two extra steps:

1. Install [Npcap](https://npcap.com/dist/) and tick **WinPcap API support**.
2. Run PowerShell as Administrator — live capture needs elevated rights.

The tool detects old consoles automatically and switches every box-drawing
character to plain ASCII, so it never crashes with `UnicodeEncodeError`.

</details>

---

## 📚 All Useful Commands

> ⚠️ **Only capture traffic on networks you own or are explicitly authorised to
> test.** On Linux, capturing needs `sudo`.

### 📁 Offline — analyse a capture file

```bash
# ── Run with a pcap file ───────────────────────────────────────
python main.py pcaps/sample.pcap                # interactive menu (the default)
python main.py                                  # asks for the path, then the menu
python main.py --help                           # every flag explained

# ── One-shot modes (no menu, always saves a report) ───────────
python main.py pcaps/sample.pcap --full            # statistics + anomalies
python main.py pcaps/sample.pcap --stats-only      # statistics only
python main.py pcaps/sample.pcap --anomalies-only  # findings only
python main.py pcaps/sample.pcap --full --no-save  # look, but write nothing
python main.py --version                           # print the version
```

<details>
<summary>🎛️ The interactive menu</summary>

| Key | Action                                           |
| :-: | :----------------------------------------------- |
| `1` | Full analysis — statistics **and** anomalies     |
| `2` | Traffic statistics only                          |
| `3` | Anomaly findings only                            |
| `4` | Save the text report + CSV summary               |
| `5` | Analyze a different capture (without restarting) |
| `h` | Show the built-in help                           |
| `0` | Exit                                             |

The menu also lists every `.pcap` it finds in `pcaps/` — including captures
written by a previous `--live` run — so you rarely have to type a path twice.

</details>

### 📡 Online — record live traffic

```bash
# ── Find out what you can record from ──────────────────────────
python main.py --list-interfaces                # names + descriptions, then exit

# ── Record, then analyse ──────────────────────────────────────
sudo python main.py --live -i eth0 -c 200 --full     # 200 packets, then report
sudo python main.py --live -i wlan0 -c 500            # Wi-Fi, interactive menu
python main.py --live --full                         # pick the interface by number

# ── Bounding the capture ──────────────────────────────────────
--count 200        stop after N packets (default 200, 0 = no limit)
--timeout 30       stop after N seconds of silence (default 30, 0 = no limit)
Ctrl+C             stop right now and analyse whatever was recorded

# ── Filtering while recording (tcpdump / BPF syntax) ──────────
--filter "port 443"                 # HTTPS only
--filter "port 53"                  # DNS only
--filter "tcp and host 10.0.0.5"    # one host, TCP only
--filter "icmp"                     # ping traffic only

# ── Different output modes ────────────────────────────────────
python main.py --live -i eth0 -c 100 --stats-only
python main.py --live -i eth0 -c 100 --anomalies-only
python main.py --live -i eth0 -c 100 --full --no-save   # don't write reports
```

Every live run also writes `pcaps/live_<timestamp>.pcap`, so you can re-open it
later offline or in Wireshark.

<details>
<summary>🧩 Full flag reference for the online mode</summary>

| Flag                | Default | Meaning                                                |
| :------------------ | :------ | :----------------------------------------------------- |
| `--live`            | off     | Record from an interface instead of reading a file     |
| `-i`, `--interface` | ask you | Interface to record from, e.g. `eth0`, `wlan0`, `en0`  |
| `-c`, `--count`     | `200`   | Stop after N packets (`0` = no limit)                  |
| `--timeout`         | `30`    | Stop after N seconds without traffic (`0` = no limit)  |
| `--filter`          | none    | tcpdump-style BPF filter, e.g. `"port 443"`            |
| `--list-interfaces` | —       | Print available interfaces and exit                    |
| `--no-save`         | off     | Skip writing reports (the live `.pcap` is still saved) |

</details>

### 👀 View results

```bash
# ── View the generated report ──────────────────────────────────
cat reports/report_2026-10-06_1218.txt            # Linux / macOS
type reports\report_2026-10-06_1218.txt           # Windows CMD
less reports/report_2026-10-06_1218.txt           # page through it

# ── View the CSV output ───────────────────────────────────────
cat output/summary_2026-10-06_1218.csv
column -s, -t < output/summary_2026-10-06_1218.csv # pretty, aligned columns
head -n 20 output/summary_2026-10-06_1218.csv      # first 20 lines only

# ── Only the interesting bits ─────────────────────────────────
grep CRITICAL reports/report_*.txt                 # worst findings
grep -i verdict reports/report_*.txt               # the verdict line
```

---

## 📡 Capture with `tcpdump` (and the Kali reference commands)

> 🐧 **`tcpdump` is the classic packet-capture tool and comes pre-installed on
> Kali Linux.** You no longer need it — `--live` does the same job inside this
> tool — but it is still the fastest way to grab a capture _without_ analyzing
> it, and it is worth knowing.
>
> 🛑 Run these only on networks you own or are authorised to test, and always
> with `sudo`.

### ✅ Find the interface that actually carries your traffic

```bash
ip -br link        # every interface, one tidy line each
ip -br addr        # the same, plus the IP addresses
sudo tcpdump -D    # only the interfaces tcpdump is allowed to open
ip route get 1.1.1.1
# → 1.1.1.1 via 192.168.1.1 dev eth0 src 192.168.1.42 uid 0
#                        ^^^^^^^^^^^ this is your interface
```

| Column / word            | Meaning                                                    |
| :----------------------- | :--------------------------------------------------------- |
| `ip -br link` first word | The value you pass to `-i`                                 |
| `UP`                     | Interface is live — **usable**                             |
| `DOWN`                   | Interface is dead — capturing here gives you **0 packets** |
| `dev eth0`               | The interface your internet traffic actually uses          |

> 🛑 **Never capture with `-i any` if you want a reliable capture.** `any` is a
> virtual catch-all pseudo-interface, so promiscuous mode is never enabled on
> the real cards, and on a switched network you only ever see _your own_
> traffic. If the terminal stays empty, you captured nothing because you
> generated nothing — start the capture, **then** browse or `ping`. A `.pcap` of
> about 24 bytes means 0 packets: that is just the pcap header.

### ✅ Prove the interface works _before_ you record anything

```bash
sudo tcpdump -i eth0 -n -c 20
```

_Prints 20 packets live, then exits by itself. Open a web page while it runs.
If packets scroll past, the interface is correct. If nothing appears, try the
next one from `ip -br link`._

### ✅ Record to a file

```bash
sudo tcpdump -i eth0 -s 0 -U -c 500 -w pcaps/my_traffic.pcap
```

| Flag      | Why it belongs in every capture                                                 |
| :-------- | :------------------------------------------------------------------------------ |
| `-i eth0` | A **real** interface, so promiscuous mode can actually be enabled               |
| `-s 0`    | Save **full** packets — the default truncates to 96 bytes and hides the payload |
| `-U`      | Write each packet out immediately, so `Ctrl+C` never leaves an empty file       |
| `-c 500`  | Stop by itself after 500 packets — no disk filling, no forgetting to stop       |
| `-n`      | No reverse-DNS lookups, so slow DNS cannot make the capture look stuck          |
| `-w file` | Write to a file instead of scrolling past on screen                             |

Then generate traffic in a **second terminal** — browse for ~30 seconds — and
verify what you actually captured:

```bash
ls -lh pcaps/my_traffic.pcap              # size on disk (must be > 24 bytes)
tcpdump -r pcaps/my_traffic.pcap -n -c 10 # first 10 packets
python main.py pcaps/my_traffic.pcap --full
```

### 🧰 Useful Tcpdump Commands

> ⚠️ **Every command below names a real interface on purpose.** Swap `eth0` for
> whatever `ip -br link` shows is `UP` on your machine.

```bash
# ── Watch traffic live on one interface ───────────────────────
sudo tcpdump -i eth0 -n

# ── Capture and save (the most important one) ─────────────────
sudo tcpdump -i eth0 -s 0 -U -c 500 -w pcaps/my_traffic.pcap

# ── Capture only port 80 (HTTP) — wakes PLAINTEXT_HTTP ────────
sudo tcpdump -i eth0 -s 0 -U port 80 -w pcaps/http.pcap

# ── Capture a limited number of packets ───────────────────────
sudo tcpdump -i eth0 -s 0 -U -c 100 -w pcaps/limited.pcap

# ── Read / view a saved pcap file (no sudo needed) ────────────
tcpdump -r pcaps/my_traffic.pcap -n
```

#### 📌 Handy extras once you know the basics

| Goal                                   | Command                                                                          |
| :------------------------------------- | :------------------------------------------------------------------------------- |
| List every interface and its state     | `ip -br link`                                                                    |
| Find the interface carrying my traffic | `ip route get 1.1.1.1`                                                           |
| List the interfaces tcpdump can open   | `sudo tcpdump -D`                                                                |
| Capture HTTPS instead                  | `sudo tcpdump -i eth0 -s 0 -U port 443 -w pcaps/https.pcap`                      |
| Capture DNS instead                    | `sudo tcpdump -i eth0 -s 0 -U port 53 -w pcaps/dns.pcap`                         |
| Capture SSH instead                    | `sudo tcpdump -i eth0 -s 0 -U port 22 -w pcaps/ssh.pcap`                         |
| Capture several ports at once          | `sudo tcpdump -i eth0 -s 0 -U "port 22 or port 3389" -w pcaps/remote.pcap`       |
| Capture one host only                  | `sudo tcpdump -i eth0 -s 0 -U host 192.168.1.50 -w pcaps/one_host.pcap`          |
| Capture only TCP SYNs (scan hunting)   | `sudo tcpdump -i eth0 -s 0 -U "tcp[tcpflags] & tcp-syn != 0" -w pcaps/syns.pcap` |
| Local traffic only                     | `sudo tcpdump -i lo -s 0 -U -c 100 -w pcaps/loopback.pcap`                       |
| Save in the newer pcapng format        | `sudo tcpdump -i eth0 -s 0 -U -J -w pcaps/traffic.pcapng`                        |
| Capture with tshark's `dumpcap`        | `dumpcap -i eth0 -w pcaps/wireshark.pcap`                                        |
| Capture on Windows (no tcpdump)        | `dumpcap -i \`Get-NetAdapter \| ? Status -eq 'Up'\` -w pcaps/win.pcap`           |
| Read a pcap without slow name lookups  | `tcpdump -r pcaps/sample.pcap -n`                                                |
| Read only the first 20 packets         | `tcpdump -r pcaps/sample.pcap -n -c 20`                                          |
| Read with readable timestamps          | `tcpdump -r pcaps/sample.pcap -n -tttt`                                          |
| Show payload as readable ASCII         | `tcpdump -r pcaps/sample.pcap -n -A`                                             |
| Count packets without storing them     | `sudo tcpdump -i eth0 -n -c 100`                                                 |

> ⚠️ **Naming a file `.pcapng` does not make it pcapng.** `tcpdump -w` always
> writes classic pcap format. Add the `-J` / `--pcapng` flag when you really
> want pcapng — the analyzer reads both, so either is fine.

<details>
<summary>📶 Capturing Wi-Fi in monitor mode</summary>

Only on a network you own or are explicitly authorised to test. In **managed**
mode `wlan0` shows your own traffic and the access point's — never another
client's frames.

```bash
sudo airmon-ng start wlan0                            # creates wlan0mon
sudo tcpdump -i wlan0mon -s 0 -U -c 500 -w pcaps/wifi_monitor.pcap
sudo airmon-ng stop wlan0mon                          # back to managed mode
```

</details>

### 🔧 Troubleshooting — still 0 packets?

| Symptom                                  | Cause                                      | Fix                                                                                                     |
| :--------------------------------------- | :----------------------------------------- | :------------------------------------------------------------------------------------------------------ |
| `0 packets captured`, nothing at all     | The interface is `DOWN`                    | Pick another one from `ip -br link`                                                                     |
| `0 packets captured`, but you browsed    | Wrong interface                            | `ip route get 1.1.1.1` and use the `dev` it names                                                       |
| `0 packets captured`, file is ~24 bytes  | Promiscuous mode never engaged             | Drop `-i any`, name the real interface, keep `sudo`                                                     |
| `Not allowed to capture` from `--live`   | Missing root / admin rights                | Prefix with `sudo` (Linux/macOS) or run PowerShell as Administrator                                     |
| `--live` says `No such interface`        | Name mismatch                              | Run `python main.py --list-interfaces` and copy the name exactly                                        |
| `--live` says the backend is unavailable | Npcap / libpcap missing                    | Windows: install Npcap; Linux: `sudo apt install libpcap0.8`                                            |
| Only your own machine's packets appear   | Switched network, promiscuous mode off     | Capture with `-i eth0` on the **host**, or from a **mirrored / SPAN port**                              |
| Empty capture inside a **VM**            | The VM has its own virtual NIC             | Capture on the **host**, or set the VM adapter to _bridged_                                             |
| Empty capture inside **WSL2**            | WSL2 is a separate VM behind a virtual NIC | Capture from **PowerShell on Windows** with `--live`, or accept that WSL only sees WSL-internal traffic |
| Empty capture inside **Docker**          | The container has its own `veth` pair      | Run the container with `--network host`, or capture on the host                                         |
| Everything looks encrypted               | Traffic runs through a VPN (`tun0`)        | `-i tun0` for the VPN side, `-i eth0` for the encrypted bytes                                           |
| `ping 127.0.0.1` captures nothing        | Loopback needs its own interface           | `sudo tcpdump -i lo -s 0 -U -c 100 -w pcaps/loopback.pcap` then run the ping                            |
| You want other clients' Wi-Fi frames     | Managed mode only ever shows your own      | `sudo airmon-ng start wlan0`, then capture `wlan0mon`                                                   |

---

## 🧠 How Anomaly Detection Works

The idea is deliberately simple: **measure, compare, explain.** And it is
identical in both modes — a live capture feeds the exact same engine.

### The three ingredients

| Ingredient          | Where it lives             | Example                                          |
| :------------------ | :------------------------- | :----------------------------------------------- |
| 📐 **Thresholds**   | ⚙️ `config.py`             | `MAX_PACKETS_FROM_SINGLE_IP = 100`               |
| 🔢 **Measurements** | 📊 `analyzer/stats.py`     | `10.0.0.9` sent 60 SYNs, none were ever answered |
| 📏 **Rules**        | 🚨 `analyzer/anomalies.py` | `if count > threshold: warnings.append(...)`     |

### How a single rule works

```python
# ⚙️ config.py  - the tunable number
MAX_PACKETS_FROM_SINGLE_IP = 100

# 🚨 analyzer/anomalies.py  - the rule that uses it
if count > config.MAX_PACKETS_FROM_SINGLE_IP:
    warnings.append(
        f"High packet volume: {ip} sent {count} packets "
        f"(threshold: {config.MAX_PACKETS_FROM_SINGLE_IP})."
    )
```

That is the whole idea. **No machine learning, no black box** — which means
you can always answer the question _"why did it warn me?"_

### 📋 The eight rules

| Rule                |   Severity   | Triggers when                                                                                | Typical real-world cause                                |
| :------------------ | :----------: | :------------------------------------------------------------------------------------------- | :------------------------------------------------------ |
| 🔫 `PORT_SCAN`      | **CRITICAL** | one IP touches more than `MAX_DISTINCT_PORTS_PER_IP` (15) different **service** ports        | nmap-style reconnaissance                               |
| 💥 `SYN_FLOOD`      | **CRITICAL** | more than `SYN_FLOOD_THRESHOLD` (50) SYNs from one IP were **never** answered with a SYN-ACK | half-open connection flood / DoS                        |
| 📈 `HIGH_VOLUME`    |   **HIGH**   | one IP sends more than `MAX_PACKETS_FROM_SINGLE_IP` (100) packets                            | scan, flood, or a very busy host                        |
| 🌐 `EXCESSIVE_DNS`  |   **HIGH**   | more than `MAX_DNS_QUERIES` (50) DNS questions in one capture                                | DNS tunnelling, DGA malware, aggressive ad scripts      |
| 🚪 `UNUSUAL_PORT`   |  **MEDIUM**  | at least `UNUSUAL_PORT_MIN_PACKETS` (3) packets to a port outside `ALLOWED_PORTS`            | backdoor, custom app, unexpected service                |
| 📡 `ICMP_FLOOD`     |  **MEDIUM**  | more than `ICMP_FLOOD_THRESHOLD` (30) ICMP packets                                           | ping sweep or DoS                                       |
| 🔓 `PLAINTEXT_HTTP` |   **LOW**    | HTTP requests are visible in the capture                                                     | unencrypted web traffic — a privacy issue, not a breach |
| 📭 `EMPTY_CAPTURE`  |   **INFO**   | the capture contains zero packets                                                            | capture stopped too early, wrong interface              |

Ports at or above `EPHEMERAL_PORT_START` (32768) are treated as return traffic
and excluded from both the port-scan count and the unusual-port warning — which
is why normal browsing stays quiet.

### 🚦 Severity levels

|     Level     | Meaning                          | What you should do               |
| :-----------: | :------------------------------- | :------------------------------- |
| 🔴 `CRITICAL` | Strong attack indicator          | Investigate immediately          |
|   🟠 `HIGH`   | Likely abuse or misconfiguration | Investigate today                |
|  🟡 `MEDIUM`  | Worth a closer look              | Check if the service is expected |
|   🔵 `LOW`    | Informational / good practice    | Consider fixing                  |
|   ⚪ `INFO`   | Context only                     | No action needed                 |

### ⚠️ Honest limitations

> Anomaly ≠ attack, and _no finding_ ≠ _safe_.
>
> - The thresholds are **static**. Real networks change, so calibrate them
>   against a known-good baseline before trusting them.
> - A **quiet capture hides everything**: encrypted traffic inside TLS cannot
>   be inspected by this tool (nor by any tool without decryption keys).
> - Missing packets (sniffing on a mirrored port) can make normal hosts look
>   like scanners.
> - A **short live capture is a biased sample**. `--count 50` over 5 seconds
>   tells you very little; give it enough traffic to be representative.

---

## 🖼️ Output Examples

All numbers below are real output from
`python main.py pcaps/attack_demo.pcap --full`, with color codes removed
(GitHub cannot show ANSI colors).

### 🎨 Terminal — traffic overview

```text
+======================+=======+
|Metric                |  Value|
+======================+=======+
|Total packets         |    365|
|Total size on wire    |16.0 KB|
|Average packet size   |44.92 B|
|Capture duration      |  18.2s|
|Unique source IPs     |      5|
|Unique destination IPs|      5|
+======================+=======+

--- > Protocols ---
+========+=======+
|Protocol|Packets|
+========+=======+
|TCP     |    124|
|UDP     |    205|
|ICMP    |     36|
|Other   |      0|
+========+=======+

--- > Top 5 Service Ports (ephemeral filtered) ---
+=+=========================+=======+=====+
|#|Port / Service           |Packets|Share|
+=+=========================+=======+=====+
|1|123 (NTP)                |    150|45.6%|
|2|4444 (Metasploit-default)|     60|18.2%|
|3|53 (DNS)                 |     55|16.7%|
|4|443 (HTTPS)              |     40|12.2%|
|5|80 (HTTP)                |      4| 1.2%|
+=+=========================+=======+=====+

--- > TCP Flags ---
+=======+=====+
|Flag   |Count|
+=======+=====+
|SYN    |  100|
|ACK    |   44|
|SYN-ACK|   20|
|PSH    |    4|
+=======+=====+
```

### 🚨 Terminal — anomaly findings

```text
+=+========+==============+=================================================+
|#|Severity|Rule          |Finding                                           |
+=+========+==============+=================================================+
|1|CRITICAL|PORT_SCAN     |Possible port scan: 192.168.1.50 contacted 20      |
| |        |              |different service ports (threshold: 15) - 20       |
| |        |              |(FTP-DATA), 21 (FTP), 22 (SSH), 23 (Telnet), 24     |
|2|CRITICAL|SYN_FLOOD     |SYN flood pattern: 10.0.0.9 sent 60 SYN packet(s) |
| |        |              |with no matching SYN-ACK (threshold: 50).          |
|3|HIGH    |HIGH_VOLUME   |High packet volume: 172.16.0.200 sent 150 packets  |
| |        |              |(threshold: 100). Possible port scan, flood or     |
| |        |              |simply a very busy host.                           |
|5|HIGH    |EXCESSIVE_DNS |Excessive DNS queries: 55 questions (threshold:    |
| |        |              |50). Possible DNS tunnelling or DGA malware.       |
|6|MEDIUM  |UNUSUAL_PORT  |Unusual port: 60 packet(s) to 4444                 |
| |        |              |(Metasploit-default). Not in the allowed list.     |
|7|MEDIUM  |ICMP_FLOOD    |High ICMP volume: 36 ICMP packets (threshold: 30).|
| |        |              |Possible ping sweep, DoS attempt or a              |
| |        |              |reachability check.                                |
|8|LOW     |PLAINTEXT_HTTP|Clear-text HTTP: 4 request(s) visible in the       |
| |        |              |capture (hosts: example.com). Traffic can be read  |
| |        |              |by anyone on the path - prefer HTTPS.               |
+=+========+==============+=================================================+

! CRITICAL - review immediately (8 findings)
> CRITICAL: 2  HIGH: 3  MEDIUM: 2  LOW: 1
```

> ☝️ _Every long message is wrapped, never cut. In your terminal the whole table
> is colored, and rows are never truncated._

### 📡 Terminal — live capture progress

```text
> Recording from eth0 · target 200 packets · stop after 30s of silence
> Filter: port 443
> Generate traffic now (open a page, ping something). Press · Ctrl+C to stop early.

  recording ████████████░░░░░░░░░░░░░░░░░░░ 86/200 packets
+ Recorded 200 packets from eth0.
+ Live capture saved -> pcaps/live_2026-10-06_1528.pcap

==================================================================
  * 01 - TRAFFIC OVERVIEW
==================================================================
```

_…and from there the same statistics, findings and reports as an offline file._

### 💾 Text report

```text
╔══════════════════════════════════════════════════════════════════════╗
║  NETWORK TRAFFIC ANALYZER - ANALYSIS REPORT                          ║
╚══════════════════════════════════════════════════════════════════════╝

  File analysed : pcaps/attack_demo.pcap
  File size     : 21.7 KB
  Generated at  : 2026-10-06_1218
  Tool version  : Network Traffic Analyzer v2.2.0
  Verdict       : CRITICAL - review immediately (8 findings)

01 TRAFFIC OVERVIEW
────────────────────────────────────────────────────────────────────────
Total packets            365
Total size           16.0 KB
Avg packet size      44.92 B
Duration               18.2s
TCP packets              124
UDP packets              205
ICMP packets              36
Unique sources             5
Unique destinations        5
DNS queries               55
HTTP requests              4

06 ANOMALY FINDINGS
────────────────────────────────────────────────────────────────────────
+-----+------------+----------------+---------------------------------+
|   # | Severity   | Rule           | Finding                         |
+=====+============+================+=================================+
|   1 | CRITICAL   | PORT_SCAN      | Possible port scan:             |
|     |            |                | 192.168.1.50 contacted 20 ...   |
|   2 | CRITICAL   | SYN_FLOOD      | SYN flood pattern: 10.0.0.9 ... |
+-----+------------+----------------+---------------------------------+

  Severity breakdown: CRITICAL=2, HIGH=3, MEDIUM=2, LOW=1

────────────────────────────────────────────────────────────────────────
  Thresholds used for this run:
    MAX_PACKETS_FROM_SINGLE_IP   = 100
    MAX_DNS_QUERIES              = 50
    MAX_DISTINCT_PORTS_PER_IP    = 15
    SYN_FLOOD_THRESHOLD          = 50
    ICMP_FLOOD_THRESHOLD         = 30
    ...
```

The report always ends with the thresholds that produced the run, so a finding
can be reproduced months later.

### 📊 CSV summary

```csv
section,metric,value
overview,Total packets,365
overview,Total size,16.0 KB
overview,Duration,18.2s
overview,DNS queries,55
protocols,TCP,124
protocols,UDP,205
top_src_ips,172.16.0.200,150
top_dst_ips,10.0.0.1,205
top_service_ports,port_4444,60
anomalies,anomaly_count,8
anomalies,verdict,CRITICAL - review immediately (8 findings)
anomalies,severity_critical,2
anomalies,finding_1,"CRITICAL | PORT_SCAN | Possible port scan: 192.168.1.50 contacted 20 different service ports ..."
```

The CSV uses a **long format** (`section, metric, value`) on purpose — it loads
straight into pandas, Excel or SQL without any cleanup:

```python
import pandas as pd
df = pd.read_csv("output/summary_2026-10-06_1218.csv")
print(df[df["section"] == "anomalies"])
```

### 🗂️ Generated files on disk

Every run leaves a trace you can diff, archive or feed into a spreadsheet:

| Path                             | Written by         | Contents                                      |
| :------------------------------- | :----------------- | :-------------------------------------------- |
| `pcaps/live_<timestamp>.pcap`    | every `--live` run | the raw capture, re-analysable offline        |
| `reports/report_<timestamp>.txt` | every saved run    | boxed human-readable report + thresholds used |
| `output/summary_<timestamp>.csv` | every saved run    | long-format metrics and findings              |

Both output folders are gitignored — captures and reports can contain sensitive
data, so they stay on your machine.

---

## ⚖️ Ethical Note

> ### ⚠️ READ THIS BEFORE YOU CAPTURE ANYTHING
>
> **Only analyse traffic that you own or have explicit written permission to
> analyse.**
>
> - 🛑 Sniffing someone else's traffic **without consent is illegal** in most
>   countries — often under computer-misuse, wiretapping or data-protection
>   laws (e.g. the Computer Fraud and Abuse Act, the UK Investigatory Powers
>   Act and the EU GDPR).
> - 📡 Live capture is **not** safer than offline analysis — in fact it is
>   riskier, because promiscuous mode on a shared network can pick up _other
>   people's_ frames that a targeted offline file never contained.
> - 🚪 Even on a network you _do_ own, tell the people who use it. Surprise
>   monitoring destroys trust.
> - 🧾 Keep a written record of the authorisation, the scope and the retention
>   period for any capture you store.
> - 🔒 A `.pcap` is extremely sensitive: it can contain passwords, session
>   cookies, personal data and other people's secrets. `--live` writes one
>   automatically into `pcaps/` — store it safely and delete it when the
>   investigation ends.
> - 🎓 This project exists for **learning and authorised security testing**.
>   It has no legitimate use for surveillance of people who have not
>   consented to it.
>
> _If you did not set it up, you did not authorise it, and you have no written
> permission — do not run the capture commands._

---

## 🚀 Future Improvements

| Status | Idea                                 | Why it is worth doing                                              |
| :----: | :----------------------------------- | :----------------------------------------------------------------- |
|   ✅   | 📡 **Live capture mode**             | shipped — `--live -i <interface>` records and analyses in one run  |
|   ✅   | 🗣️ **Real-browsing service tagging** | shipped — DNS names are mapped to YouTube / Google / Instagram / … |
|   ✅   | 🔌 **Ephemeral-port filtering**      | shipped — return traffic no longer triggers false positives        |
|   ⬜   | 📊 **HTML report with charts**       | one self-contained file, no internet needed                        |
|   ⬜   | 🕐 **Traffic timeline**              | packets-per-second sparkline to spot bursts visually               |
|   ⬜   | 🔁 **Baseline comparison**           | diff two captures and report only what _changed_                   |
|   ⬜   | 🌍 **Geo / ASN lookup**              | offline whois database to flag unusual destinations                |
|   ⬜   | 🧠 **Per-IP traffic profiles**       | bandwidth, session count and idle time per host                    |
|   ⬜   | 🧪 **Unit tests**                    | pytest fixtures with tiny generated pcaps                          |
|   ⬜   | 🔌 **Plugin rules**                  | load custom detection rules from a `rules/` folder                 |
|   ⬜   | 🖼️ **GUI front-end**                 | optional Tkinter or web UI over the same analyzer package          |
|   ⬜   | 📦 **PyInstaller build**             | ship it as a single `.exe` for the lab                             |

---

## 👤 Author & Credits

<div align="center">

### 🧑‍💻 Built by

**GURRALA KISHORE KUMAR** — cybersecurity student & aspiring network defender

> ✏️ Update `AUTHOR` in [`config.py`](config.py) and this section before you publish.

</div>

---

### 🎓 Stand on the shoulders of giants

| Project                                           | Role                                                                      |
| :------------------------------------------------ | :------------------------------------------------------------------------ |
| 🧬 [Scapy](https://scapy.net/)                    | Packet crafting, parsing **and live capture** — the engine under the hood |
| 🎨 [colorama](https://pypi.org/project/colorama/) | Cross-platform ANSI colors                                                |
| 📑 [tabulate](https://pypi.org/project/tabulate/) | Pretty tables inside the reports                                          |
| 🐧 [Kali Linux](https://www.kali.org/)            | The reference environment for this project                                |
| 🦈 [Wireshark](https://www.wireshark.org/)        | For looking at captures by hand                                           |
| 🐧 [tcpdump](https://www.tcpdump.org/)            | For capturing and quick-filtering pcaps                                   |
| 🧬 [Npcap](https://npcap.com/dist/)               | The Windows capture backend used by `--live`                              |

### 📚 Learn more

- [Scapy documentation](https://scapy.readthedocs.io/en/latest/)
- [Scapy — sniffing tutorial](https://scapy.readthedocs.io/en/latest/api/scapy.sendrecv.html)
- [Wireshark sample captures](https://wiki.wireshark.org/SampleCaptures) — free pcaps to test with
- [The Wireshark Wiki](https://wiki.wireshark.org/) — filter cheat sheets and protocol references
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework) — where detection fits in a real program

---

## 📜 License

Released under the **[MIT License](LICENSE)** — use it, learn from it, improve it,
teach with it. Just keep the copyright notice.

---

<div align="center">

### 🚀 Ready to analyze some traffic?

```bash
# offline - analyse a capture you already have
python main.py pcaps/attack_demo.pcap --full

# online - record live traffic and analyse it in the same run
sudo python main.py --live -i eth0 -c 200 --full
```

**Made with 🧠, ☕ and a healthy respect for privacy.**

⭐ _If this project helped you learn something, consider starring it._

</div>
