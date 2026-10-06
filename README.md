<div align="center">

# 🛰️ Network Traffic Analyzer

### *Read a `.pcap` file. Understand the traffic. Catch what does not belong.*

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Kali Linux](https://img.shields.io/badge/Kali%20Linux-ready-367bf2?style=for-the-badge&logo=kali-linux&logoColor=white)](https://www.kali.org/)
[![Scapy](https://img.shields.io/badge/Scapy-2.5%2B-blue?style=for-the-badge&logo=python&logoColor=white)](https://scapy.net/)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey?style=for-the-badge)](#-requirements)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![No Root](https://img.shields.io/badge/analysis-no%20root%20needed-brightgreen?style=for-the-badge)](#-installation)
[![Code style](https://img.shields.io/badge/code%20style-documented-blue?style=for-the-badge)](#-project-structure)

`pcap insights` · `anomaly detection` · `zero cloud calls`

</div>

---

## 📖 What is this?

A **beginner-friendly, fully offline** command-line tool that reads packet captures
(`.pcap` / `.pcapng`), shows beautiful traffic statistics, and flags anything that
looks suspicious — using rules you can actually read and understand.

| 🧩 | 💡 Why it exists |
|:--|:--|
| 🧮 **Real statistics** | Packets, bytes, duration, protocols, top talkers, top ports, DNS domains, TCP flags |
| 🚨 **8 explainable rules** | Port scans, SYN floods, volume spikes, odd ports, DNS abuse, ICMP floods, clear-text HTTP |
| 🎯 **Severity grading** | Every finding is `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` or `INFO` — sorted worst-first |
| 🎨 **Premium terminal UI** | Boxed banner, colored tables, ANSI-aware alignment, automatic ASCII fallback |
| 💾 **Reports you can keep** | A boxed `.txt` report for humans and a long-format `.csv` for Excel / pandas / SQL |
| 🔌 **Works offline** | Reads a file you already have — the tool never touches the network |

> 💡 **TL;DR** — capture (or download) a `.pcap`, drop it in `pcaps/`, run one command, read the verdict.

> 🧰 **Capturing for the first time?** Read
> [🧰 How to Capture Traffic Properly](#-how-to-capture-traffic-properly) before
> you type `tcpdump`. It explains why `-i any` produces `0 packets captured`
> and gives you a command that works every time.

---

## ⚡ Quick Start

Copy-paste these three blocks and you are analyzing traffic in under a minute.

```bash
# 1️⃣  Install the dependencies
cd network-traffic-analyzer
pip install -r requirements.txt
```

```bash
# 2️⃣  Run the interactive menu on a capture
python main.py pcaps/sample.pcap
```

```bash
# 3️⃣  Or get the full picture in one shot, no menu, report saved
python main.py pcaps/sample.pcap --full
```

<details>
<summary>🐧 Kali Linux? Use these commands instead</summary>

```bash
# Kali ships pip in "externally managed" mode, so either use a virtualenv...
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# ...or override the guard (fine for a throwaway analysis VM):
pip install --break-system-packages -r requirements.txt
```

</details>

🎁 **No capture handy?** Two demo files are already waiting for you:

| File | What it contains |
|:--|:--|
| 📄 `pcaps/sample.pcap` | 10 small, harmless packets — perfect for a first run |
| 🎬 `pcaps/attack_demo.pcap` | 365 packets that **deliberately trigger every rule** (scan, SYN flood, DNS flood, ICMP flood, plaintext HTTP…) |

```bash
python main.py pcaps/attack_demo.pcap --full   # see the tool light up red
```

---

## ✨ Features

| | Feature | What you get |
|:--|:--|:--|
| 📊 | **Traffic overview** | Total packets, total bytes, average frame size, capture duration, unique source/destination IPs |
| 🌐 | **Protocol breakdown** | TCP / UDP / ICMP / Other counts with a share of the total |
| 🗣️ | **Top talkers** | Top 5 source IPs, destination IPs, source ports and destination ports (with service names) |
| 🔍 | **DNS insight** | How many queries, and which domains were asked for most |
| 🚩 | **TCP flags** | SYN / ACK / SYN-ACK / RST / FIN / PSH counters |
| 🕵️ | **Anomaly detection** | 8 rules, each graded by severity, sorted worst-first |
| 🖥️ | **Interactive menu** | Re-display any section, save reports, or switch files without restarting |
| ⚡ | **One-shot CLI modes** | `--full`, `--stats-only`, `--anomalies-only`, `--no-save` — perfect for scripts |
| 💾 | **Report generation** | Boxed `.txt` report + long-format `.csv`, both timestamped |
| 🪟 | **Cross-platform** | Linux, macOS and Windows — with a graceful ASCII fallback on old consoles |
| 🧠 | **No black boxes** | Every threshold lives in `config.py`, every rule is a short readable function |
| 🔒 | **Offline & private** | No telemetry, no API calls, no uploads. Ever. |

---

## 🗂️ Project Structure

```text
network-traffic-analyzer/
│
├── 📄 README.md               ← you are here
├── 📜 LICENSE                 ← MIT
├── 📦 requirements.txt        ← scapy, colorama, tabulate
├── ⚙️  config.py               ← ALL thresholds live here (edit this first!)
│
├── 🚀 main.py                  ← CLI entry point: parse args, orchestrate, exit
│
├── 🧠 analyzer/
│   ├── 📘 __init__.py          ← package docstring + version
│   ├── 🛠️  utils.py             ← load captures, format bytes/duration, text width
│   ├── 📊 stats.py             ← one pass over the packets → all statistics
│   ├── 🚨 anomalies.py         ← 8 rules → severity-graded findings
│   ├── 🎨 ui.py                ← every color, glyph and ANSI-aware table
│   └── 💾 report.py            ← .txt report + .csv summary writers
│
├── 📁 pcaps/                   ← put your captures here
│   ├── sample.pcap             ← tiny demo capture (10 packets)
│   └── attack_demo.pcap        ← demo capture that triggers every rule
│
├── 📁 reports/                 ← generated: report_<timestamp>.txt
└── 📁 output/                  ← generated: summary_<timestamp>.csv
```

### 🧭 Which file do I edit?

| I want to… | Open |
|:--|:--|
| Change how suspicious something must be before it is flagged | ⚙️ `config.py` |
| Add a new detection rule | 🚨 `analyzer/anomalies.py` |
| Add a new statistic (e.g. count ARP packets) | 📊 `analyzer/stats.py` |
| Change colors, the banner or the tables | 🎨 `analyzer/ui.py` |
| Change what the saved report contains | 💾 `analyzer/report.py` |

---

## 🔧 Installation

### 📋 Requirements

| Requirement | Version | Note |
|:--|:--|:--|
| 🐍 Python | 3.9 or newer | `python3 --version` |
| 🧬 Scapy | 2.5+ | reads `.pcap` / `.pcapng` |
| 🎨 colorama | 0.4.6+ | colors that also work on Windows |
| 📑 tabulate | 0.9+ | aligned tables inside the reports |
| 🧬 libpcap | usually pre-installed on Kali | only needed by Scapy for live sniffing |

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

The tool detects old consoles automatically and switches every box-drawing
character to plain ASCII, so it never crashes with `UnicodeEncodeError`.

</details>

<details>
<summary>🐧 Kali Linux notes</summary>

```bash
# Kali marks pip as externally managed → prefer a venv (above).
# If you really do not want a venv:
pip install --break-system-packages -r requirements.txt

# tcpdump and tshark are already installed on Kali, so the capture
# commands in the "All Useful Commands" section work out of the box.
```

</details>

---

## 📚 All Useful Commands

> ⚠️ **Only run the capture commands on networks you own or are explicitly
> authorised to test.** On Linux, capturing usually needs `sudo`.

### 🎯 Capture Traffic

> 🛑 **Never capture with `-i any` if you want a reliable capture.** It is the
> single most common reason for a 0-packet `.pcap`. Always name the real
> interface. See
> [🧰 How to Capture Traffic Properly](#-how-to-capture-traffic-properly) for
> the full explanation and the fix.

> 👉 **New to tcpdump?** Jump straight to
> [🧰 How to Capture Traffic Properly](#-how-to-capture-traffic-properly) —
> it walks through the whole process one step at a time.

```bash
# 💡 First: find out which interfaces exist and which one carries your traffic
ip -br link                          # every interface, one line each
ip route get 1.1.1.1                 # ← the answer: "dev eth0" / "dev wlan0"
sudo tcpdump -D                      # only the interfaces tcpdump can open

# ── Capture variants (always a REAL interface) ───────────────
sudo tcpdump -i eth0 -s 0 -w pcaps/full.pcap          # wired, full packets
sudo tcpdump -i wlan0 -s 0 -w pcaps/wifi.pcap         # Wi-Fi
sudo tcpdump -i lo -s 0 -w pcaps/loopback.pcap        # local traffic only
sudo dumpcap -i eth0 -w pcaps/wireshark.pcap          # with tshark's dumpcap

# ── Other protocols / bigger samples ─────────────────────────
sudo tcpdump -i eth0 -s 0 -c 500 -w pcaps/sample.pcap         # stop at 500 pkts
sudo tcpdump -i eth0 -s 0 port 443 -w pcaps/https.pcap        # HTTPS
sudo tcpdump -i eth0 -s 0 port 53 -w pcaps/dns.pcap           # DNS
sudo tcpdump -i eth0 -s 0 port 22 -w pcaps/ssh.pcap           # SSH
sudo tcpdump -i eth0 -s 0 "port 22 or port 3389" -w pcaps/remote.pcap
```

### 🚀 Run the Tool

```bash
# ── Run with a pcap file ───────────────────────────────────────
python main.py pcaps/sample.pcap                # interactive menu (the default)

# ── Run and see menu options ───────────────────────────────────
python main.py pcaps/sample.pcap                # menu appears right after loading
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

| Key | Action |
|:--:|:--|
| `1` | Full analysis — statistics **and** anomalies |
| `2` | Traffic statistics only |
| `3` | Anomaly findings only |
| `4` | Save the text report + CSV summary |
| `5` | Analyze a different capture (without restarting) |
| `h` | Show the built-in help |
| `0` | Exit |

The menu also lists every `.pcap` it finds in `pcaps/`, so you rarely have to
type a path twice.

</details>

### 👀 View Results

```bash
# ── View the generated report ──────────────────────────────────
cat reports/report_2026-10-03_1217.txt            # Linux / macOS
type reports\report_2026-10-03_1217.txt           # Windows CMD
less reports/report_2026-10-03_1217.txt           # page through it

# ── View the CSV output ───────────────────────────────────────
cat output/summary_2026-10-03_1217.csv
column -s, -t < output/summary_2026-10-03_1217.csv # pretty, aligned columns
head -n 20 output/summary_2026-10-03_1217.csv      # first 20 lines only

# ── Only the interesting bits ─────────────────────────────────
grep CRITICAL reports/report_*.txt                 # worst findings
grep -i verdict reports/report_*.txt               # the verdict line
```

## 🧰 How to Capture Traffic Properly

> 🎯 **This section fixes the `0 packets captured` problem.** Read it once and
> every capture you make from now on will work.

### ❌ Why `-i any` gives you 0 packets

`any` is **not a real network card**. On Linux it is a virtual catch-all
pseudo-interface that libpcap emulates with a raw packet socket. Three things
follow from that, and together they explain the output you saw:

```text
sudo tcpdump -i any -w my_ip_traffic.pcap
WARNING: That device doesn't support promiscuous mode   ← (1) harmless noise
0 packets captured
0 packets received by filter                            ← (2) the real problem
```

| # | What happened | Why it matters |
|:--|:--|:--|
| 1️⃣ | **`WARNING: ... promiscuous mode`** | `any` is virtual, so it *cannot* be put into promiscuous mode. This warning is **expected and is not the bug** — ignore it safely. |
| 2️⃣ | **Promiscuous mode never gets enabled on the real cards** | The request was made on `any`, so `eth0` / `wlan0` stay in normal mode. A switch only forwards frames addressed to your MAC, so every frame belonging to *another* machine is dropped by the NIC before tcpdump ever sees it. |
| 3️⃣ | **You did not generate any traffic** | `tcpdump` records frames that *actually pass by*. Start the capture, **then** browse or run `ping`. An idle interface legitimately produces an empty file. |

**Net effect:** on a switched network `-i any` usually shows you *only your own*
traffic — and if you sit and watch the terminal without doing anything, it shows
you *nothing*.

> 💡 **The rule:** `-i any` is fine for a 5-second live glance at the terminal.
> For anything you intend to **save and analyze, always name the real interface**
> (`eth0`, `wlan0`, `enp3s0`, …).

### ✅ Step 1 — Find the interface that actually carries your traffic

```bash
ip -br link        # every interface, one tidy line each
ip -br addr        # the same, plus the IP addresses
sudo tcpdump -D    # only the interfaces tcpdump is allowed to open
```

```text
$ ip -br link
lo           UNKNOWN  <BROADCAST,LOOPBACK,UP>  ...
enp3s0       UP       <BROADCAST,MULTICAST,UP>  ...
wlan0        DOWN     <BROADCAST,MULTICAST>     ...
```

Read it like this:

| Column | Meaning |
|:--|:--|
| First word | The value you pass to `-i` |
| `UP` | Interface is live — **usable** |
| `DOWN` | Interface is dead — capturing here gives you **0 packets** |

Not sure which card carries your internet traffic? Ask the routing table:

```bash
ip route get 1.1.1.1
# → 1.1.1.1 via 192.168.1.1 dev eth0 src 192.168.1.42 uid 0
#                        ^^^^^^^^^^^ this is your interface
```

### ✅ Step 2 — Prove the interface works *before* you record anything

```bash
sudo tcpdump -i eth0 -n -c 20
```

_Prints 20 packets live, then exits by itself. Open a web page while it runs.
If packets scroll past, the interface is correct. If nothing appears, try the
next one from `ip -br link`._

### ✅ Step 3 — Record to a file (the command you actually want)

```bash
sudo tcpdump -i eth0 -s 0 -U -c 500 -w pcaps/my_traffic.pcap
```

| Flag | Why it belongs in every capture |
|:--|:--|
| `-i eth0` | A **real** interface, so promiscuous mode can actually be enabled |
| `-s 0` | Save **full** packets — the default truncates to 96 bytes and hides the payload |
| `-U` | Write each packet out immediately, so `Ctrl+C` never leaves an empty file |
| `-c 500` | Stop by itself after 500 packets — no disk filling, no forgetting to stop |
| `-n` | No reverse-DNS lookups, so slow DNS cannot make the capture look stuck |
| `-w file` | Write to a file instead of scrolling past on screen |

### ✅ Step 4 — Generate traffic while it captures

`tcpdump` records frames that pass by, so open a **second terminal**: capture in
terminal 1, traffic in terminal 2.

**Terminal 1 — start the capture**
```bash
sudo tcpdump -i eth0 -s 0 -U -c 500 -w pcaps/my_traffic.pcap
```

**Terminal 2 — make something happen**
```bash
ping -c 20 1.1.1.1                          # ICMP  → wakes ICMP_FLOOD
curl -s https://example.com -o /dev/null    # HTTPS → ordinary web traffic
nslookup example.com                        # DNS   → wakes EXCESSIVE_DNS
curl -s http://neverssl.com -o /dev/null    # HTTP  → wakes PLAINTEXT_HTTP
```

> 🧠 **Rule of thumb:** a capture during which you did nothing is a capture with
> nothing in it. Thirty seconds of browsing is enough.

### ✅ Step 5 — Verify the file before you analyze it

```bash
ls -lh pcaps/my_traffic.pcap                    # size on disk
tcpdump -r pcaps/my_traffic.pcap -n -c 10       # first 10 packets
```

```text
-rw------- 1 root root 148K Sep 30 21:14 pcaps/my_traffic.pcap
reading from file pcaps/my_traffic.pcap, link-type EN10MB (Ethernet)
21:14:03.481 IP 192.168.1.42.51234 > 142.250.185.78.443: Flags [S], ...
```

> 🚨 **A file of about 24 bytes means 0 packets.** Those 24 bytes are just the
> pcap header — the capture never worked. Go back to Step 1.

### ✅ Step 6 — Analyze it

```bash
python main.py pcaps/my_traffic.pcap --full
```

### 🔧 Troubleshooting — still 0 packets?

| Symptom | Cause | Fix |
|:--|:--|:--|
| `0 packets captured`, nothing at all | The interface is `DOWN` | Pick another one from `ip -br link` |
| `0 packets captured`, but you browsed | Wrong interface | `ip route get 1.1.1.1` and use the `dev` it names |
| `0 packets captured`, file is ~24 bytes | Promiscuous mode never engaged | Drop `-i any`, name the real interface, keep `sudo` |
| Only your own machine's packets appear | Switched network, promiscuous mode off | Capture with `-i eth0` on the **host**, or from a **mirrored / SPAN port** |
| `bind()` fails, "You don't have permission" | Not root | Prefix the command with `sudo` |
| Empty capture inside a **VM** | The VM has its own virtual NIC | Capture on the **host**, or set the VM adapter to *bridged* |
| Empty capture inside **WSL2** | WSL2 is a separate VM behind a virtual NIC | Capture from **PowerShell on Windows** with `dumpcap`, or accept that WSL only sees WSL-internal traffic |
| Empty capture inside **Docker** | The container has its own `veth` pair | Run the container with `--network host`, or capture on the host |
| Everything looks encrypted | Traffic runs through a VPN (`tun0`) | `-i tun0` for the VPN side, `-i eth0` for the encrypted bytes |
| `ping 127.0.0.1` captures nothing | Loopback needs its own interface | `sudo tcpdump -i lo -s 0 -U -c 100 -w pcaps/loopback.pcap` then run the ping |
| You want other clients' Wi-Fi frames | Managed mode only ever shows your own | `sudo airmon-ng start wlan0`, then capture `wlan0mon` |

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

---

## 🧰 Useful Tcpdump Commands

> 🐧 **`tcpdump` is the classic packet-capture tool and comes pre-installed on
> Kali Linux.** It only *creates* the `.pcap` file — the **Network Traffic
> Analyzer** does all the analysis afterwards.
>
> 🛑 Run these only on networks you own or are authorised to test, and always
> with `sudo`.
>
> ⚠️ **Every command below names a real interface on purpose.** Swap `eth0` for
> whatever `ip -br link` shows is `UP` on your machine.
> Never use `-i any` for a capture you plan to analyze — see
> [🧰 How to Capture Traffic Properly](#-how-to-capture-traffic-properly).

---

#### 1️⃣ Watch traffic live on one interface

```bash
sudo tcpdump -i eth0 -n
```

_Watches **one** named interface and prints each packet live. Press `Ctrl+C` to
stop. Use `wlan0` for Wi-Fi and `lo` for local-only traffic._

---

#### 2️⃣ Capture and save to a pcap file ⭐

```bash
sudo tcpdump -i eth0 -s 0 -U -c 500 -w pcaps/my_traffic.pcap
```

_The **most important** command: it saves the capture into
`pcaps/my_traffic.pcap` instead of only printing it. That file is what you
analyze next. Every flag is explained in Step 3 of
[🧰 How to Capture Traffic Properly](#-how-to-capture-traffic-properly)._

---

#### 3️⃣ Capture only port 80 (HTTP) traffic

```bash
sudo tcpdump -i eth0 -s 0 -U port 80 -w pcaps/http.pcap
```

_Keeps **only HTTP packets** and drops everything else — useful when you want a
small, focused capture of web browsing. This is what triggers the
`PLAINTEXT_HTTP` rule._

---

#### 4️⃣ Capture a limited number of packets

```bash
sudo tcpdump -i eth0 -s 0 -U -c 100 -w pcaps/limited.pcap
```

_Stops automatically after **100 packets** (`-c` = count), so the file stays
small and you never fill the disk._

---

#### 5️⃣ Read / view a saved pcap file

```bash
tcpdump -r pcaps/my_traffic.pcap -n
```

_Replays a capture that already exists on disk, so you can confirm what is
inside it before analyzing it. **No `sudo` needed** — reading a file does not
touch the network._

---

#### 📌 Handy extras once you know the basics

| Goal | Command |
|:--|:--|
| List every interface and its state | `ip -br link` |
| Find the interface carrying my traffic | `ip route get 1.1.1.1` |
| List the interfaces tcpdump can open | `sudo tcpdump -D` |
| Keep full packets (not truncated) | `sudo tcpdump -i eth0 -s 0 -w pcaps/full.pcap` |
| Stop after a bigger sample | `sudo tcpdump -i eth0 -s 0 -U -c 1000 -w pcaps/big.pcap` |
| Capture HTTPS instead | `sudo tcpdump -i eth0 -s 0 -U port 443 -w pcaps/https.pcap` |
| Capture DNS instead | `sudo tcpdump -i eth0 -s 0 -U port 53 -w pcaps/dns.pcap` |
| Capture SSH instead | `sudo tcpdump -i eth0 -s 0 -U port 22 -w pcaps/ssh.pcap` |
| Capture several ports at once | `sudo tcpdump -i eth0 -s 0 -U "port 22 or port 3389" -w pcaps/remote.pcap` |
| Capture one host only | `sudo tcpdump -i eth0 -s 0 -U host 192.168.1.50 -w pcaps/one_host.pcap` |
| Capture only TCP SYNs (scan hunting) | `sudo tcpdump -i eth0 -s 0 -U "tcp[tcpflags] & tcp-syn != 0" -w pcaps/syns.pcap` |
| Save in the newer pcapng format | `sudo tcpdump -i eth0 -s 0 -U -J -w pcaps/traffic.pcapng` |
| Capture with tshark's `dumpcap` | `dumpcap -i eth0 -w pcaps/wireshark.pcap` |
| Capture on Windows (no tcpdump) | `dumpcap -i \`Get-NetAdapter \| ? Status -eq 'Up'\` -w pcaps/win.pcap` |
| Read a pcap without slow name lookups | `tcpdump -r pcaps/sample.pcap -n` |
| Read only the first 20 packets | `tcpdump -r pcaps/sample.pcap -n -c 20` |
| Read with readable timestamps | `tcpdump -r pcaps/sample.pcap -n -tttt` |
| Show payload as readable ASCII | `tcpdump -r pcaps/sample.pcap -n -A` |
| Count packets without storing them | `tcpdump -i eth0 -n -c 100` |

> ⚠️ **Naming a file `.pcapng` does not make it pcapng.** `tcpdump -w` always
> writes classic pcap format. Add the `-J` / `--pcapng` flag when you really
> want pcapng — the analyzer reads both, so either is fine.

> 💡 **Where does the file go?**
> `tcpdump -w` writes into your **current folder** — but if you give it a path
> like `pcaps/my_traffic.pcap`, it writes exactly there. Run the command from
> inside the project folder and always point `-w` at `pcaps/`, or move the file
> afterwards with `mv my_traffic.pcap pcaps/`.

<details>
<summary>🔁 From capture to verdict — copy/paste chain</summary>

```bash
# 1. find your interface (note the one that is UP and carries your traffic)
ip -br link
ip route get 1.1.1.1

# 2. capture — browse the web in a second terminal for ~30 seconds
sudo tcpdump -i eth0 -s 0 -U -c 500 -w pcaps/my_traffic.pcap

# 3. check what you actually captured (expect real packets, not 24 bytes)
tcpdump -r pcaps/my_traffic.pcap -n -c 20

# 4. analyze it
python main.py pcaps/my_traffic.pcap --full
```

</details>

---

## 🔄 Complete Workflow

> Follow these six steps the very first time. Every step shows the exact command
> **and** what you should see.

### Step 1️⃣ — Set up 🛠️

```bash
cd network-traffic-analyzer
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python main.py --version
```

**✅ Expected:** `Network Traffic Analyzer 2.1.0`

---

### Step 2️⃣ — Get a capture file 📥

**Option A — capture your own traffic** 🧰

Follow [🧰 How to Capture Traffic Properly](#-how-to-capture-traffic-properly)
first. The short version is these two commands:

```bash
# 1. find the interface that is UP and carries your traffic
ip route get 1.1.1.1

# 2. capture on THAT interface, then browse the web for ~30 seconds
sudo tcpdump -i eth0 -s 0 -U -c 500 -w pcaps/my_capture.pcap
```

> 🚫 **Do not use `-i any`.** It is the number-one cause of
> `0 packets captured` — the full reasoning is in
> [🧰 How to Capture Traffic Properly](#-how-to-capture-traffic-properly).

**Option B — use the bundled demo captures** 🎁

```bash
ls pcaps/
# attack_demo.pcap   sample.pcap
```

**✅ Expected:** the file exists in `pcaps/` **and is bigger than 24 bytes** —
check with `ls -lh pcaps/my_capture.pcap`.

---

### Step 3️⃣ — Launch the analyzer 🚀

```bash
python main.py pcaps/my_capture.pcap
```

**✅ Expected:** the boxed banner, then `✔ Loaded N packets.`, then the menu

---

### Step 4️⃣ — Choose what to see 🎛️

| You want | Press |
|:--|:--|
| Everything | `1` then Enter |
| Only the numbers | `2` then Enter |
| Only the warnings | `3` then Enter |
| Save the reports | `4` |

**✅ Expected:** `01 · TRAFFIC OVERVIEW` and/or `02 · ANOMALY FINDINGS`

---

### Step 5️⃣ — Save the reports 💾

Press `4`, or run the one-shot version:

```bash
python main.py pcaps/my_capture.pcap --full
```

**✅ Expected:**

```text
✔ Text report saved  → reports/report_2026-10-03_1217.txt
✔ CSV summary saved  → output/summary_2026-10-03_1217.csv
```

---

### Step 6️⃣ — Read the verdict 📋

```bash
cat reports/report_2026-10-03_1217.txt
```

**✅ Expected:** a boxed report ending with a one-line **verdict**, for example
`CRITICAL - review immediately (13 findings)`.

---

### 🌳 The whole flow at a glance

```text
   ┌─────────────────┐
   │  find the iface │   ip -br link  /  ip route get 1.1.1.1
   └────────┬────────┘
            ▼
   ┌─────────────────┐
   │  capture .pcap  │   sudo tcpdump -i eth0 -s 0 -U -c 500 \
   │  (NOT -i any)   │            -w pcaps/my_capture.pcap
   └────────┬────────┘
            ▼
   ┌─────────────────┐
   │  verify it has  │   tcpdump -r pcaps/my_capture.pcap -n -c 20
   │  real packets   │   ⚠ a 24-byte file means the capture failed
   └────────┬────────┘
            ▼
   ┌─────────────────┐
   │  python main.py │   python main.py pcaps/my_capture.pcap
   └────────┬────────┘
            ▼
   ┌─────────────────┐
   │  load packets   │   Scapy reads every frame ONCE
   └────────┬────────┘
            ▼
   ┌─────────────────┐
   │ compute stats   │   protocols · talkers · ports · DNS · TCP flags
   └────────┬────────┘
            ▼
   ┌─────────────────┐
   │ run 8 rules     │   compare numbers against config.py thresholds
   └────────┬────────┘
            ▼
   ┌─────────────────┐
   │  show verdict   │   CRITICAL → HIGH → MEDIUM → LOW → INFO
   └────────┬────────┘
            ▼
   ┌─────────────────┐
   │ save reports    │   reports/report_*.txt  +  output/summary_*.csv
   └─────────────────┘
```

---

## 🧠 How Anomaly Detection Works

The idea is deliberately simple: **measure, compare, explain.**

### The three ingredients

| Ingredient | Where it lives | Example |
|:--|:--|:--|
| 📐 **Thresholds** | ⚙️ `config.py` | `MAX_PACKETS_FROM_SINGLE_IP = 100` |
| 🔢 **Measurements** | 📊 `analyzer/stats.py` | `10.0.0.9` sent 60 SYNs, none were ever answered |
| 📏 **Rules** | 🚨 `analyzer/anomalies.py` | `if count > threshold: warnings.append(...)` |

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
you can always answer the question *"why did it warn me?"*

### 📋 The eight rules

| Rule | Severity | Triggers when | Typical real-world cause |
|:--|:--:|:--|:--|
| 🔫 `PORT_SCAN` | **CRITICAL** | one IP touches more than `MAX_DISTINCT_PORTS_PER_IP` (15) different destination ports | nmap-style reconnaissance |
| 💥 `SYN_FLOOD` | **CRITICAL** | more than `SYN_FLOOD_THRESHOLD` (50) SYNs from one IP were **never** answered with a SYN-ACK | half-open connection flood / DoS |
| 📈 `HIGH_VOLUME` | **HIGH** | one IP sends more than `MAX_PACKETS_FROM_SINGLE_IP` (100) packets | scan, flood, or a very busy host |
| 🌐 `EXCESSIVE_DNS` | **HIGH** | more than `MAX_DNS_QUERIES` (50) DNS questions in one capture | DNS tunnelling, DGA malware, aggressive ad scripts |
| 🚪 `UNUSUAL_PORT` | **MEDIUM** | traffic to a port outside `ALLOWED_PORTS` | backdoor, custom app, unexpected service |
| 📡 `ICMP_FLOOD` | **MEDIUM** | more than `ICMP_FLOOD_THRESHOLD` (30) ICMP packets | ping sweep or DoS |
| 🔓 `PLAINTEXT_HTTP` | **LOW** | HTTP requests are visible in the capture | unencrypted web traffic — a privacy issue, not a breach |
| 📭 `EMPTY_CAPTURE` | **INFO** | the capture contains zero packets | capture stopped too early, wrong interface |

### 🚦 Severity levels

| Level | Meaning | What you should do |
|:--:|:--|:--|
| 🔴 `CRITICAL` | Strong attack indicator | Investigate immediately |
| 🟠 `HIGH` | Likely abuse or misconfiguration | Investigate today |
| 🟡 `MEDIUM` | Worth a closer look | Check if the service is expected |
| 🔵 `LOW` | Informational / good practice | Consider fixing |
| ⚪ `INFO` | Context only | No action needed |

### ⚠️ Honest limitations

> Anomaly ≠ attack, and *no finding* ≠ *safe*.
>
> - The thresholds are **static**. Real networks change, so calibrate them
>   against a known-good baseline before trusting them.
> - A **quiet capture hides everything**: encrypted traffic inside TLS cannot
>   be inspected by this tool (nor by any tool without decryption keys).
> - Missing packets (sniffing on a mirrored port) can make normal hosts look
>   like scanners.

---

## 🖼️ Output Examples

### 🎨 Terminal — traffic overview

```text
╔══════════════════════╦═══════╗
│Metric                │  Value│
╞══════════════════════╪═══════╣
│Total packets         │    365│
│Total size on wire    │16.0 KB│
│Average packet size   │44.92 B│
│Capture duration      │  18.2s│
│Unique source IPs     │      5│
│Unique destination IPs│      5│
╚══════════════════════╩═══════╝

─── ▸ Protocols ───
╔════════╦═══════╗
│Protocol│Packets│
╞════════╪═══════╣
│TCP     │    124│
│UDP     │    205│
│ICMP    │     36│
│Other   │      0│
╚════════╩═══════╝
```

### 🚨 Terminal — anomaly findings

```text
╔══╦════════╦════════════╦══════════════════════════════════════════╗
│# │Severity │Rule        │Finding                                   ║
╞══╪════════╪════════════╪══════════════════════════════════════════╣
│1 │CRITICAL │PORT_SCAN   │Possible port scan: 192.168.1.50 contacted│
│  │         │            │20 different ports (threshold: 15)       │
│2 │CRITICAL │SYN_FLOOD   │SYN flood pattern: 10.0.0.9 sent 60 SYN   │
│  │         │            │packet(s) with no matching SYN-ACK.      │
│3 │HIGH     │HIGH_VOLUME │High packet volume: 172.16.0.200 sent 150 │
│  │         │            │packets (threshold: 100).                 │
╚══╩════════╩════════════╩══════════════════════════════════════════╝

⚠ CRITICAL - review immediately (13 findings)
▸ CRITICAL: 2  HIGH: 3  MEDIUM: 6  LOW: 1  INFO: 1
```

> ☝️ *(Real output from `python main.py pcaps/attack_demo.pcap --full`, trimmed
> to the first three findings and with the color codes removed — GitHub cannot
> show ANSI colors. In your terminal the whole table is colored and every long
> message is wrapped, never cut.)*

### 💾 Text report

```text
╔══════════════════════════════════════════════════════════════════════════╗
║  NETWORK TRAFFIC ANALYZER - ANALYSIS REPORT                            ║
╚══════════════════════════════════════════════════════════════════════════╝

  File analysed : pcaps/attack_demo.pcap
  File size     : 21.7 KB
  Generated at  : 2026-10-03_1217
  Tool version  : Network Traffic Analyzer v2.1.0
  Verdict       : CRITICAL - review immediately (13 findings)

01 TRAFFIC OVERVIEW
────────────────────────────────────────────────────────────────────────────
Total packets              365
Total size            16.0 KB
Duration               18.2s
DNS queries               55
────────────────────────────────────────────────────────────────────────────

06 ANOMALY FINDINGS
────────────────────────────────────────────────────────────────────────────
  #  Severity   Rule       Finding
  1  CRITICAL   PORT_SCAN  Possible port scan: 192.168.1.50 contacted 20 ...
  2  CRITICAL   SYN_FLOOD  SYN flood pattern: 10.0.0.9 sent 60 SYN ...

  Severity breakdown: CRITICAL=2, HIGH=3, MEDIUM=6, LOW=1, INFO=1
```

### 📊 CSV summary

```csv
section,metric,value
overview,Total packets,365
overview,Total size,16.0 KB
overview,Duration,18.2s
protocols,TCP,124
protocols,UDP,205
top_src_ips,172.16.0.200,150
top_dst_ports,port_123,150
anomalies,anomaly_count,13
anomalies,verdict,CRITICAL - review immediately (13 findings)
anomalies,severity_critical,2
anomalies,finding_1,CRITICAL | PORT_SCAN | Possible port scan: 192.168.1.50 ...
```

The CSV uses a **long format** (`section, metric, value`) on purpose — it loads
straight into pandas, Excel or SQL without any cleanup:

```python
import pandas as pd
df = pd.read_csv("output/summary_2026-10-03_1217.csv")
print(df[df["section"] == "anomalies"])
```

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
> - 🚪 Even on a network you *do* own, tell the people who use it. Surprise
>   monitoring destroys trust.
> - 🧾 Keep a written record of the authorisation, the scope and the retention
>   period for any capture you store.
> - 🔒 A `.pcap` is extremely sensitive: it can contain passwords, session
>   cookies, personal data and other people's secrets. Store it safely and
>   delete it when the investigation ends.
> - 🎓 This project exists for **learning and authorised security testing**.
>    It has no legitimate use for surveillance of people who have not
>    consented to it.
>
> *If you did not set it up, you did not authorise it, and you have no written
> permission — do not run the capture commands.*

---

## 🚀 Future Improvements

| Status | Idea | Why it is worth doing |
|:--:|:--|:--|
| ⬜ | 📊 **HTML report with charts** | one self-contained file, no internet needed |
| ⬜ | 🕐 **Traffic timeline** | packets-per-second sparkline to spot bursts visually |
| ⬜ | 🔁 **Baseline comparison** | diff two captures and report only what *changed* |
| ⬜ | 📡 **Live capture mode** | analyze packets straight from an interface with Scapy's `sniff()` |
| ⬜ | 🌍 **Geo / ASN lookup** | offline whois database to flag unusual destinations |
| ⬜ | 🧠 **Per-IP traffic profiles** | bandwidth, session count and idle time per host |
| ⬜ | 🧪 **Unit tests** | pytest fixtures with tiny generated pcaps |
| ⬜ | 🔌 **Plugin rules** | load custom detection rules from a `rules/` folder |
| ⬜ | 🖼️ **GUI front-end** | optional Tkinter or web UI over the same analyzer package |
| ⬜ | 📦 **PyInstaller build** | ship it as a single `.exe` for the lab |

---

## 👤 Author & Credits

<div align="center">

### 🧑‍💻 Built by

**Your Name** — cybersecurity student & aspiring network defender

> ✏️ Update `AUTHOR` in [`config.py`](config.py) and this section before you publish.

</div>

---

### 🎓 Stand on the shoulders of giants

| Project | Role |
|:--|:--|
| 🧬 [Scapy](https://scapy.net/) | Packet crafting and parsing — the engine under the hood |
| 🎨 [colorama](https://pypi.org/project/colorama/) | Cross-platform ANSI colors |
| 📑 [tabulate](https://pypi.org/project/tabulate/) | Pretty tables inside the reports |
| 🐧 [Kali Linux](https://www.kali.org/) | The reference environment for this project |
| 🦈 [Wireshark](https://www.wireshark.org/) | For looking at captures by hand |
| 🐧 [tcpdump](https://www.tcpdump.org/) | For capturing and quick-filtering pcaps |

### 📚 Learn more

- [Scapy documentation](https://scapy.readthedocs.io/en/latest/)
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
python main.py pcaps/attack_demo.pcap --full
```

**Made with 🧠, ☕ and a healthy respect for privacy.**

⭐ *If this project helped you learn something, consider starring it.*

</div>
