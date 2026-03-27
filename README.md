<div align="center">  

# 🔍 PrivAudit

### *Next-Generation Linux Privilege Escalation Auditor*

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/platform-Linux-lightgrey.svg)](https://www.linux.org)

**Intelligent • Accurate • Low-Noise • Production-Ready**

</div>  

---

## 🎯 Overview

**PrivAudit** is a modern Linux privilege escalation auditing tool designed to go beyond traditional enumeration.

Instead of overwhelming you with raw findings, PrivAudit focuses on:

* **Accuracy over noise**
* **Real attack paths**
* **Reliable exploit guidance**

It answers the questions that actually matter during a pentest:

* What can be exploited?
* How can it be exploited?
* How reliable is it?
* What is the fastest path to root?

---

## ⚡ Why PrivAudit?

| Feature          | Traditional Tools | PrivAudit                         |
| ---------------- | ----------------- | --------------------------------- |
| Output Noise     | ❌ High            | ✅ Minimal & Clean                 |
| Attack Paths     | ❌ None            | ✅ Ranked & Realistic              |
| Exploit Guidance | ❌ Generic         | ✅ Reliability-based               |
| False Positives  | ❌ Common          | ✅ Filtered (real path resolution) |
| Risk Scoring     | ❌ Basic           | ✅ Dynamic & weighted              |

---

## ✨ Features

### 🔍 Intelligent Scanning

* Modular scanning engine
* Real path resolution (eliminates symlink false positives)
* Accurate permission checks using `stat()`
* Smart filtering of system paths and pseudo-files

---

### 🧠 Risk Scoring System

* Severity-based scoring (CRITICAL → INFO)
* Reliability-aware weighting
* Impact-based scaling (Root vs User)
* Final risk level classification

---

### 💣 Exploit Suggestions

* Verified techniques (inspired by GTFOBins logic)
* Reliability indicators:

  * **HIGH** → reliable
  * **CONDITIONAL** → depends on environment
  * **LOW** → manual testing required
* Step-by-step guidance

---

### 🔗 Attack Path Analysis (Core Feature)

* Chains vulnerabilities into real escalation paths
* Identifies:

  * ⚡ Fastest path
  * 🔒 Most reliable path
* Includes:

  * Likelihood
  * Time-to-exploit
  * Required steps

---

### 📊 Professional Reporting

* Clean CLI output
* JSON export (automation-ready)
* Markdown reports (pentest-ready)

---

## 🛡️ Detection Modules

| Module       | Description                                    |
| ------------ | ---------------------------------------------- |
| SUID         | Detect exploitable SUID binaries               |
| Sudo         | Identify misconfigurations (ALL:ALL, NOPASSWD) |
| Permissions  | Writable sensitive files                       |
| Cron         | Writable or unsafe cron jobs                   |
| Capabilities | Dangerous Linux capabilities                   |
| Docker       | Docker group privilege escalation              |
| Kernel       | Kernel version analysis                        |
| PATH         | Writable directories in PATH                   |

---

## 📦 Installation

```bash
git clone https://github.com/ben/priv-audit.git
cd priv-audit
pip install -r requirements.txt
chmod +x main.py
```

---

## 🚀 Usage

### Basic Commands

```bash
# Full audit
python3 main.py --full

# Quick audit
python3 main.py --quick

# Markdown report
python3 main.py --full --output report.md

# JSON report
python3 main.py --full --json report.json

# Verbose mode
python3 main.py --full --verbose
```

---

### With Sudo (Recommended)

```bash
sudo python3 main.py --full
```

Without sudo, some checks may be limited (cron, SUID, capabilities).

---

## 📖 Command Line Options

| Option          | Description              |
| --------------- | ------------------------ |
| `--full`        | Run all checks           |
| `--quick`       | Run critical checks only |
| `--output FILE` | Generate Markdown report |
| `--json FILE`   | Generate JSON report     |
| `--verbose`     | Debug output             |

---

## 💡 Example Output

```
📊 SUMMARY
----------------------------------
Total Findings: 7
Critical: 1
High: 2
Medium: 2

Risk Level: MEDIUM

🎯 ATTACK PATHS
----------------------------------
FASTEST PATH: Sudo → Root (100%)

⚡ QUICK WINS
----------------------------------
1. Full sudo access
2. PATH hijack
```

---

## 🔗 Attack Path Concept

PrivAudit builds realistic chains like:

```
User → Writable PATH → Malicious Binary → Root
User → SUID Binary → Root Shell
User → Sudo Misconfig → Root
```

---

## 🎯 Risk Scoring

Formula:

```
Score = Severity × Reliability × Impact
```

### Severity

* CRITICAL = 10
* HIGH = 6
* MEDIUM = 3
* LOW = 1

### Reliability

* HIGH = 1.0
* MEDIUM = 0.7
* CONDITIONAL = 0.5
* LOW = 0.3

### Impact

* Root = 1.0
* User = 0.5

---

## 📄 Report Formats

### JSON

* Machine-readable
* Automation-ready

### Markdown

* Pentest-style
* Client-ready documentation

---

## 🏗️ Architecture

```
priv-audit/
│
├── core/
├── checks/
├── output/
├── utils/
├── main.py
```

Modular design allows easy extension and new checks.

---

## 🤝 Contributing

Contributions are welcome.

Steps:

1. Create new check in `checks/`
2. Follow modular structure
3. Register in scanner
4. Submit PR

---

## 📝 License

MIT License

---

<div align="center">

**Built with Python 🐍**
by **Ben**

**PrivAudit — Audit. Analyze. Elevate.**

</div>
