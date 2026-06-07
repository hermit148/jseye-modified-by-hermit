# JSEye - Ultimate JavaScript Intelligence & Attack Surface Discovery Engine

<div align="center">
  <img src="https://img.shields.io/badge/Python-3.8%2B-blue.svg" alt="Python Version"/>
  <img src="https://img.shields.io/badge/Status-Modified%20by%20H3RM!T-brightgreen" alt="Status"/>
  <img src="https://img.shields.io/badge/License-MIT-blue" alt="License"/>
</div>

JSEye is an enterprise-grade, fully automated attack surface discovery and JavaScript analysis engine designed for security engineers, bug bounty hunters, and red teamers. 

Going far beyond simple regex crawling, JSEye orchestrates a high-performance, 6-tool Go pipeline (`gau`, `waybackurls`, `hakrawler`, `subfinder`, `katana`, `mantra`) combined with headless browser rendering, DOM flow vulnerability tracing, and constant propagation variable tracking.

This custom branch has been **heavily optimized, debugged, and modified by H3RM!T**.

---

## 🏗️ Codebase Structure

```
jseye_modified/
├── install.sh             # Automated Unix installer script
├── requirements.txt       # Python dependencies list
├── setup.py               # Python setuptools packaging script
├── patch_template.py      # Template patching utility
├── jseye/                 # Main JSEye package directory
│   ├── cli.py             # CLI parser and output console display
│   ├── installer.py       # Pre-flight environment check & Go compiler
│   ├── os_detect.py       # OS-specific binary search path & utility installer
│   ├── version.py         # Version definition
│   ├── core/              # Core processing engines
│   │   ├── ast_engine.py          # Variable assignment and constant propagation
│   │   ├── collector.py           # Web scraper and script downloader
│   │   ├── cve_engine.py          # Library vulnerability lookup (OSV.dev integration)
│   │   ├── dom_flow.py            # DOM XSS flow analyzer (sources & sinks)
│   │   ├── headless.py            # Playwright headless browser wrapper
│   │   ├── secret_engine.py       # Multi-factor secret scoring validation
│   │   └── utils.py               # Parsing and normalized utilities
│   ├── data/              # Internal configuration data files
│   │   └── regex_patterns.json    # Secrets & endpoints regex database
│   ├── plugins/           # Extensible plugins directory
│   │   ├── base.py                # Plugin specifications
│   │   ├── manager.py             # Plugin runner and manager
│   │   └── ...                    # API, CVE, DOM, Secret plugins
│   └── report/            # Report generation modules
│       ├── html_report.py         # Jinja2 template HTML report builders
│       ├── json_report.py         # Machine-readable report formatters
│       └── templates/             # Beautiful, interactive HTML template
│           └── report.html
└── jseye-3.0.1.dist-info/ # Package installation metadata
```

---

## 🛠️ Modifications & Improvements (by H3RM!T)

This customized version addresses critical issues present in the original codebase:

1. **Memory Leak Prevention**: Rewrote page context handling in [`headless.py`](file:///c:/Users/H3RM!T/Downloads/Telegram%20Desktop/jseye_modified/jseye/core/headless.py) to guarantee all Playwright page contexts are closed in `finally` blocks, stopping Chromium process leaks on page runtime exceptions.
2. **Broken API Removals**: Decompiled and removed the non-functional, unauthenticated MITRE API search from [`cve_engine.py`](file:///c:/Users/H3RM!T/Downloads/Telegram%20Desktop/jseye_modified/jseye/core/cve_engine.py), transitioning dependency checks exclusively to the robust OSV.dev registry.
3. **Concurrency Optimization**: Re-engineered sequential page fetching in [`collector.py`](file:///c:/Users/H3RM!T/Downloads/Telegram%20Desktop/jseye_modified/jseye/core/collector.py) to run concurrent script/source extraction using `asyncio.gather()`.
4. **Syntax-Safe Cleanups**: Fixed comment cleanups in [`utils.py`](file:///c:/Users/H3RM!T/Downloads/Telegram%20Desktop/jseye_modified/jseye/core/utils.py) to avoid stripping double slashes `//` inside literal strings, protecting URLs from parser corruption.
5. **SPA Target Support**: Modified URL normalization in [`utils.py`](file:///c:/Users/H3RM!T/Downloads/Telegram%20Desktop/jseye_modified/jseye/core/utils.py) to preserve hash routing fragments (e.g. `#/dashboard`), enabling the tool to scrape modern SPA frameworks.
6. **Mantra Installation**: Updated Mantra installation configurations to map correct repository redirects (`github.com/brosck/mantra`).
7. **Custom Modification Branding**: Integrated the `Modified by H3RM!T` attribute into the ASCII banners, HTML watermarks, footers, JSON reports, and argparse terminal configurations.

---

## 🚀 Installation & Setup

### Automated Installation (Unix-like systems: Linux, macOS)
You can clone the repository and run the provided automated installer script to configure python dependencies and headless browsers:

```bash
git clone <repository_url>
cd jseye_modified
chmod +x install.sh
./install.sh
```

### Manual Installation
Alternatively, install requirements manually:

1. Install Python packages:
   ```bash
   pip install .
   ```
2. Install Playwright browser dependencies:
   ```bash
   playwright install chromium
   ```

*(Note: Go is recommended in your system path on first execution so JSEye can compile missing external tools during pre-flight checks).*

---

## 🎯 Usage

To scan a target using smart default parameters:
```bash
jseye target.com
```

To run complete scans with all features enabled (Ultimate Hunter Mode):
```bash
jseye target.com --all
```
