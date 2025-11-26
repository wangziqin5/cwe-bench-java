"""
从 NVD REST API v2 获取 CVE 元数据。

示例:
    python cve_fetcher.py CVE-2021-12345 --outfile CVE-2021-12345.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict


API_ROOT = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_USER_AGENT = "cve-bench-java-tools/1.0"
DEFAULT_OUTPUT_DIR = Path(__file__).resolve().parent / "cve_info"


def fetch_cve(cve_id: str, api_key: str | None = None, timeout: int = 30) -> Dict[str, Any]:
    """从 NVD REST API 获取单个 CVE ID 的元数据。"""
    params = urllib.parse.urlencode({"cveId": cve_id})
    request = urllib.request.Request(f"{API_ROOT}?{params}", method="GET")
    request.add_header("User-Agent", DEFAULT_USER_AGENT)
    if api_key:
        request.add_header("apiKey", api_key)

    with urllib.request.urlopen(request, timeout=timeout) as response:
        payload = json.loads(response.read().decode("utf-8"))

    if not payload.get("vulnerabilities"):
        raise ValueError(f"CVE '{cve_id}' not found in NVD response.")
    return payload


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cve_id", help="目标 CVE 标识符，例如 CVE-2021-12345。")
    parser.add_argument(
        "--api-key",
        dest="api_key",
        default=None,
        help="可选的 NVD API 密钥（回退到 NVD_API_KEY 环境变量）。",
    )
    parser.add_argument(
        "--outfile",
        default=None,
        help="写入 JSON 响应的路径。覆盖 --output-dir。",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="存储 CVE JSON 文件的目录 (默认: tools/cve_info)。",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="HTTP 超时（秒）(默认: 30)。",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    api_key = args.api_key or os.getenv("NVD_API_KEY")

    try:
        result = fetch_cve(args.cve_id, api_key=api_key, timeout=args.timeout)
    except urllib.error.HTTPError as exc:
        print(f"[cve_fetcher] HTTP error: {exc.code} {exc.reason}", file=sys.stderr)
        return 1
    except urllib.error.URLError as exc:
        print(f"[cve_fetcher] Network error: {exc.reason}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"[cve_fetcher] {exc}", file=sys.stderr)
        return 1

    if args.outfile:
        outfile_path = Path(args.outfile)
        outfile_path.parent.mkdir(parents=True, exist_ok=True)
    else:
        output_dir = args.output_dir or DEFAULT_OUTPUT_DIR
        output_dir.mkdir(parents=True, exist_ok=True)
        outfile_path = output_dir / f"{args.cve_id}.json"

    with outfile_path.open("w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2)
    print(f"[cve_fetcher] Wrote data to {outfile_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

