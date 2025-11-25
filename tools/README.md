# Custom Analysis Tools

This folder contains utility scripts that complement the CWE-Bench-Java
dataset when running on Windows or other environments where the original
automation might need extra tooling.

## `cve_fetcher.py`

- Fetches the complete metadata for a given CVE ID from the public NVD REST
  API v2.
- Usage:
  ```
  python cve_fetcher.py CVE-2021-12345 --api-key <optional-key> --outfile data.json
  ```
- Features:
  - Works without an API key (lower rate limit) or with one via CLI flag or
    `NVD_API_KEY` environment variable.
  - Gracefully handles networking errors and missing CVEs.

## `vuln_function_extractor.py`

- Reads `data/fix_info.csv`, finds the recorded method/class ranges for a
  project, and copies the vulnerable function bodies from
  `project-sources/<project_slug>/...`.
- Usage:
  ```
  python vuln_function_extractor.py --project apache__camel_CVE-2018-8041_2.20.3 --output out_dir
  ```
- Features:
  - Falls back to class ranges when method ranges are missing.
  - Supports dumping snippets to files or printing to stdout.
  - Designed to run on Windows (no Unix-only tools required).

