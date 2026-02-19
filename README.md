# PowerShell.Solarwinds

## Search SolarWinds (NCM & IPAM)

`search-solarwinds.ps1` is a PowerShell script that searches SolarWinds NCM configuration archives and IPAM via the SolarWinds REST API.  
It finds devices and IPs that match a given search term (name or IP) and prints human‑readable tables.

---

## Features

- **NCM search**: Looks for the search term inside running configs downloaded in the last _N_ days.
- **IPAM search**: Looks up IP addresses and reverse DNS entries that match the search term.
- **Deduplicated results**: For NCM, it returns only the latest running config per device and hides devices with “Standby” in their name.
- **REST API based**: Uses the SolarWinds Information Service v3 JSON API.
- **Tested in PowerShell 7**.

---

> **Note**: The script disables certificate validation for `Invoke-WebRequest` and `Invoke-RestMethod`. Use this only in trusted environments or update it to enforce proper certificate validation.

---

## Configuration

The script loads credentials and host information from a PowerShell environment file in the current user’s home directory:

- **File**: `$HOME/.env.ps1`
