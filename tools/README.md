# Custom Analysis Tools

This folder contains utility scripts that complement the CWE-Bench-Java
dataset when running on Windows or other environments where the original
automation might need extra tooling.

## `cve_fetcher.py`

- Fetches the complete metadata for a given CVE ID from the public NVD REST
  API v2.
- By default each run writes a JSON file to `tools/cve_outputs/<CVE>.json`.
  Use `--output-dir` to change the folder or `--outfile` for a fully custom
  path.
- Usage:
  ```
  python cve_fetcher.py CVE-2021-12345 --api-key <optional-key>
  ```
- Features:
  - Works without an API key (lower rate limit) or with one via CLI flag or
    `NVD_API_KEY` environment variable.
  - Gracefully handles networking errors and missing CVEs.

## `vuln_function_extractor.py`

- Reads `data/fix_info.csv`, finds the recorded method/class ranges for a
  project, and copies the vulnerable function bodies.
- **No full repo clone required** – only the referenced files are downloaded
  (via GitHub raw URLs) when missing. You can still point to an existing
  checkout via `--sources-root`.
- Usage:
  ```
  python vuln_function_extractor.py --project apache__camel_CVE-2018-8041_2.20.3
  ```
- Features:
  - Automatically fetches only the necessary files for each snippet.
  - Stores snippets under `tools/vuln_snippets/<project_slug>/...` by default;
    pass `--output <dir>` to override or `--output -` to print to stdout.
  - Optional caching directory (`--cache-root`, default `.cache/vuln_sources`).
  - Falls back to class ranges when method ranges are missing.
  - Supports dumping snippets to files or printing to stdout.
  - Designed to run on Windows (no Unix-only tools required).

