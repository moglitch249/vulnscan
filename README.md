# VulnScanner — Vulnerability Assessment & Intelligence Framework

> **⚠️ AUTHORIZED USE ONLY:** This tool is intended exclusively for authorized security assessments, owned infrastructure, security labs, and CTF environments. Do not use against systems you do not have explicit permission to test.

## Overview

VulnScanner is a production-quality Python CLI tool for:

- **Network discovery** — live hosts, TCP ports, services, versions, OS fingerprinting
- **Software fingerprinting** — CPE normalization, PURL generation, vendor/product/version extraction
- **Vulnerability intelligence** — querying 15+ public vulnerability databases and feeds
- **Vulnerability correlation** — deduplication, cross-referencing, and enrichment
- **Risk assessment** — transparent, evidence-based risk scoring with full traceability
- **Reporting** — JSON, CSV, HTML dashboard with remediation information

## Architecture

```
vulnscanner/
│
├── cli/                    # Typer-based CLI commands
├── core/
│   ├── models.py           # Pydantic domain models
│   ├── interfaces.py       # VulnerabilitySource ABC
│   ├── scanner_base.py     # ScannerIntegration ABC
│   ├── config.py           # Configuration loading
│   ├── validators.py       # Input validation
│   ├── http_client.py      # Resilient HTTP client
│   └── logging.py          # Structured logging
│
├── sources/                # Vulnerability intelligence source plugins
│   ├── nvd/                # NIST NVD API 2.0
│   ├── kev/                # CISA KEV catalog
│   ├── osv/                # OSV.dev API
│   ├── epss/               # FIRST EPSS API + bulk CSV
│   ├── ghsa/               # GitHub Security Advisories (GraphQL)
│   ├── vulncheck/          # VulnCheck Community API
│   ├── exploitdb/          # Exploit-DB (local git clone)
│   └── vendors/            # Debian, Red Hat, Alpine, etc.
│
├── integrations/           # External scanner tools
│   ├── nmap/               # Nmap integration
│   ├── httpx/              # httpx integration
│   └── ...
│
├── database/               # SQLite / PostgreSQL persistence
├── cache/                  # Response caching layer
├── tests/                  # pytest test suite
└── main.py                 # CLI entry point
```

## Installation

```bash
# Clone the repository
git clone <repository-url>
cd vulnscanner

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
# or: .venv\Scripts\activate  # Windows

# Install in development mode
pip install -e ".[dev]"

# Copy and configure environment
cp .env.example .env
# Edit .env with your API keys
```

### Requirements

- **Python 3.12+**
- **Nmap** (must be installed and on PATH for network scanning)
- Optional: httpx, dnsx, naabu for extended scanning

### API Keys

| Source | Key Required | Free Tier | Get Key |
|--------|:---:|:---:|---------|
| NVD | Optional | Yes (5 req/30s without key) | [nvd.nist.gov](https://nvd.nist.gov/developers/request-an-api-key) |
| CISA KEV | No | Public JSON feed | — |
| OSV.dev | No | No rate limits | — |
| EPSS | No | Public API + CSV | — |
| GHSA | Recommended | 5000 req/hr with PAT | [github.com/settings/tokens](https://github.com/settings/tokens) |
| VulnCheck | Yes | 1000 req/min (Community) | [vulncheck.com](https://vulncheck.com) |
| Debian Tracker | No | Public JSON feed | — |
| Red Hat | No | Public CSAF/VEX (CC BY 4.0) | — |
| Alpine SecDB | No | Public JSON feed | — |
| Exploit-DB | No | Local git clone | — |

## CLI Usage

```bash
# Scan a single target
vulnscan scan --target 192.168.1.10

# Scan a CIDR range
vulnscan scan --target 10.0.0.0/24 --profile standard

# Web-focused scan
vulnscan scan --target https://example.com --profile web

# Full deep scan
vulnscan scan --target 10.10.10.5 --profile deep

# Offline mode (use cached databases only)
vulnscan scan --target 192.168.1.0/24 --offline

# Import Nmap XML
vulnscan scan --target 192.168.1.10 --scan-file scan.xml

# Look up a CVE
vulnscan cve CVE-2024-12345

# Search by product
vulnscan search --product apache --vendor apache

# Search by CPE
vulnscan search --cpe "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"

# Update offline databases
vulnscan update

# Check source health
vulnscan health

# List sources
vulnscan sources

# Show configuration (secrets redacted)
vulnscan config

# Generate report
vulnscan report scan_data.db --format html
```

## Scan Profiles

| Profile | Description | Ports | Service Detection | OS Detection |
|---------|-------------|-------|:-:|:-:|
| `quick` | Fast host discovery (ping sweep) | — | ✗ | ✗ |
| `standard` | Top 1000 ports + service versions | Top 1000 | ✓ | ✗ |
| `deep` | All 65535 ports + version + OS + scripts | All | ✓ | ✓ |
| `web` | HTTP/S ports + technology fingerprinting | 80,443,8080,8443 | ✓ | ✗ |

## Configuration

- **`.env`** — API keys and secrets (never committed)
- **`config.yaml`** — Scanner behavior, source settings, profiles, reporting

See [.env.example](.env.example) and [config.yaml](config.yaml) for all options.

## Database Architecture

SQLite is used by default. Tables:

| Table | Purpose |
|-------|---------|
| `targets` | Input targets per scan |
| `hosts` | Discovered hosts |
| `ports` | Open ports per host |
| `services` | Services per port |
| `software` | Normalized fingerprints |
| `cpe_mappings` | CPE → software mappings |
| `vulnerabilities` | Correlated vulnerability records |
| `vulnerability_sources` | Per-source raw results |
| `exploits` | Public exploit references |
| `advisories` | Vendor advisories |
| `scan_runs` | Scan metadata and status |
| `findings` | Vulnerability → host/service bindings |
| `raw_responses` | Cached API responses with TTL |

## Adding a New Vulnerability Source

1. Create a new module in `vulnscanner/sources/`
2. Implement the `VulnerabilitySource` abstract class from `vulnscanner.core.interfaces`
3. Register the source in the source registry
4. Add configuration to `config.yaml`
5. Write tests using mock responses (no real API keys required)

```python
from vulnscanner.core.interfaces import VulnerabilitySource

class MyNewSource(VulnerabilitySource):
    @property
    def name(self) -> str:
        return "MySource"

    @property
    def capabilities(self) -> set[str]:
        return {"search_cve", "search_product"}

    # ... implement all abstract methods
```

If the source cannot be legally/technically integrated:

```python
from vulnscanner.core.interfaces import NotImplementedSource

my_source = NotImplementedSource(
    source_name="PaidOnlyDB",
    reason="Requires enterprise license with no public API",
)
```

## Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=vulnscanner --cov-report=html

# Run fast tests only
pytest -m "not slow"

# Skip integration tests
pytest -m "not integration"
```

Tests do **not** require real API keys — all external calls are mocked.

## Development

```bash
# Lint
ruff check vulnscanner/ tests/

# Format
ruff format vulnscanner/ tests/

# Type check
mypy vulnscanner/
```

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `nmap not found` | Install Nmap and ensure it's on PATH |
| NVD rate limited | Add `NVD_API_KEY` to `.env` for 50 req/30s |
| GHSA auth error | Create a GitHub PAT and set `GITHUB_TOKEN` |
| VulnCheck 401 | Sign up for free Community tier at vulncheck.com |
| Offline scan missing data | Run `vulnscan update` first |

## License

MIT License. See [LICENSE](LICENSE).

## Legal Notice

This tool is provided for **authorized security testing only**. Users are responsible for:

- Obtaining explicit written authorization before scanning any target
- Complying with all applicable laws and regulations
- Understanding that unauthorized scanning may be illegal
- Using the tool only against owned infrastructure, authorized targets, or lab/CTF environments

The authors accept no liability for misuse of this software.
