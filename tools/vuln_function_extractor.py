"""
提取 data/fix_info.csv 中记录的易受攻击的函数体。
仅自动下载所需的源文件（无需完整的 repo 克隆）。

示例:
    python vuln_function_extractor.py CVE-2018-8041
"""

from __future__ import annotations

import argparse
import csv
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional


REPO_ROOT = Path(__file__).resolve().parents[1]
FIX_INFO_PATH = REPO_ROOT / "data" / "fix_info.csv"
PROJECT_INFO_PATH = REPO_ROOT / "data" / "project_info.csv"
DEFAULT_CACHE_ROOT = Path(__file__).resolve().parent / "cache"
DEFAULT_OUTPUT_DIR = Path(__file__).resolve().parent / "vuln_code"
RAW_GITHUB_BASE = "https://raw.githubusercontent.com"


@dataclass
class FixEntry:
    project_slug: str
    file_path: str
    method: str
    class_name: str
    start_line: int
    end_line: int


@dataclass
class ProjectInfo:
    project_slug: str
    cve_id: str
    github_username: str
    github_repository_name: str
    buggy_commit_id: str


PROJECT_INFO_MAP: Dict[str, ProjectInfo] = {}


def safe_int(value: Optional[str]) -> Optional[int]:
    if value is None:
        return None
    stripped = value.strip()
    if not stripped:
        return None
    try:
        return int(stripped)
    except ValueError:
        return None


def load_entries(project_slug: str, csv_path: Path) -> List[FixEntry]:
    entries: List[FixEntry] = []
    with csv_path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            if row["project_slug"] != project_slug:
                continue

            method_start = safe_int(row.get("method_start"))
            method_end = safe_int(row.get("method_end"))
            class_start = safe_int(row.get("class_start"))
            class_end = safe_int(row.get("class_end"))

            start_line = method_start or class_start
            end_line = method_end or class_end
            if start_line is None or end_line is None:
                print(
                    f"[extractor] Skipping {row['file']} (missing line numbers)",
                    file=sys.stderr,
                )
                continue

            entries.append(
                FixEntry(
                    project_slug=row["project_slug"],
                    file_path=row["file"],
                    method=row.get("method") or "<class-scope>",
                    class_name=row.get("class") or "",
                    start_line=start_line,
                    end_line=end_line,
                )
            )
    if not entries:
        raise ValueError(
            f"No entries found for project '{project_slug}'. "
            "Ensure fix_info.csv contains this slug."
        )
    return entries


def read_snippet(source_file: Path, start_line: int, end_line: int) -> str:
    if not source_file.exists():
        raise FileNotFoundError(
            f"Source file '{source_file}' does not exist. "
            "The project may not have been downloaded correctly."
        )

    lines = source_file.read_text(encoding="utf-8", errors="ignore").splitlines()
    total_lines = len(lines)
    if start_line < 1 or end_line > total_lines:
        raise ValueError(
            f"Line range {start_line}-{end_line} is outside the bounds of "
            f"{source_file} ({total_lines} lines)."
        )
    snippet = "\n".join(lines[start_line - 1 : end_line])
    return snippet


def sanitize_filename(fragment: str) -> str:
    safe_chars = []
    for ch in fragment:
        if ch.isalnum() or ch in ("-", "_"):
            safe_chars.append(ch)
        else:
            safe_chars.append("_")
    return "".join(safe_chars)


def load_project_info() -> None:
    if PROJECT_INFO_MAP:
        return
    with PROJECT_INFO_PATH.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            PROJECT_INFO_MAP[row["project_slug"]] = ProjectInfo(
                project_slug=row["project_slug"],
                cve_id=row["cve_id"],
                github_username=row["github_username"],
                github_repository_name=row["github_repository_name"],
                buggy_commit_id=row["buggy_commit_id"],
            )


def get_project_info(project_slug: str) -> ProjectInfo:
    load_project_info()
    project_info = PROJECT_INFO_MAP.get(project_slug)
    if not project_info:
        raise ValueError(f"Project '{project_slug}' not found in project_info.csv")
    return project_info


def get_projects_by_cve(cve_id: str) -> List[ProjectInfo]:
    load_project_info()
    results = [p for p in PROJECT_INFO_MAP.values() if p.cve_id == cve_id]
    if not results:
        raise ValueError(f"No projects found for CVE ID '{cve_id}' in project_info.csv")
    return results


def download_source_file(
    project_info: ProjectInfo,
    relative_path: str,
    cache_root: Path,
) -> Path:
    normalized_path = relative_path.replace("\\", "/")
    target_path = cache_root / project_info.project_slug / project_info.buggy_commit_id / relative_path
    target_path.parent.mkdir(parents=True, exist_ok=True)

    raw_url = (
        f"{RAW_GITHUB_BASE}/"
        f"{project_info.github_username}/"
        f"{project_info.github_repository_name}/"
        f"{project_info.buggy_commit_id}/"
        f"{normalized_path}"
    )

    try:
        with urllib.request.urlopen(raw_url) as response:
            data = response.read()
    except urllib.error.HTTPError as exc:
        raise FileNotFoundError(
            f"Failed to fetch '{raw_url}' (HTTP {exc.code})."
        ) from exc
    except urllib.error.URLError as exc:
        raise ConnectionError(
            f"Failed to download '{raw_url}': {exc.reason}"
        ) from exc

    target_path.write_bytes(data)
    return target_path


def resolve_source_file(
    project_slug: str,
    relative_path: str,
    sources_root: Optional[Path],
    cache_root: Path,
) -> Path:
    project_info = get_project_info(project_slug)

    # 如果文件存在于用户提供的 sources_root 中，则优先使用。
    if sources_root:
        candidate = sources_root / project_slug / relative_path
        if candidate.exists():
            return candidate

    # 回退到缓存版本（如有必要则下载）。
    cached_file = cache_root / project_slug / project_info.buggy_commit_id / relative_path
    if cached_file.exists():
        return cached_file

    return download_source_file(project_info, relative_path, cache_root)


def dump_snippets(
    entries: Iterable[FixEntry],
    sources_root: Optional[Path],
    cache_root: Path,
    output_dir: Optional[Path] = None,
) -> None:
    wrote_files = False
    for idx, entry in enumerate(entries, start=1):
        source_path = resolve_source_file(
            entry.project_slug,
            entry.file_path,
            sources_root,
            cache_root,
        )
        snippet = read_snippet(source_path, entry.start_line, entry.end_line)
        header = (
            f"{entry.project_slug} :: {entry.file_path} :: "
            f"{entry.method} ({entry.start_line}-{entry.end_line})"
        )
        if output_dir:
            target_dir = output_dir / entry.project_slug
            target_dir.mkdir(parents=True, exist_ok=True)
            file_stub = sanitize_filename(Path(entry.file_path).name)
            target_path = target_dir / f"{idx:03d}_{file_stub}.txt"
            with target_path.open("w", encoding="utf-8") as handle:
                handle.write(header + "\n")
                handle.write("=" * len(header) + "\n\n")
                handle.write(snippet)
                handle.write("\n")
            wrote_files = True
        else:
            print(header)
            print("=" * len(header))
            print(snippet)
            print()
    if output_dir and wrote_files:
        print(f"[extractor] Wrote snippets to '{output_dir}'.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "cve_id",
        help="目标 CVE 标识符，例如 CVE-2021-12345。",
    )
    parser.add_argument(
        "--fix-info",
        type=Path,
        default=FIX_INFO_PATH,
        help="fix_info.csv 的路径 (默认: data/fix_info.csv)。",
    )
    parser.add_argument(
        "--sources-root",
        type=Path,
        default=None,
        help="包含 project-sources/<project_slug> 的基本目录。 "
        "如果省略，文件将从 GitHub 单独获取。",
    )
    parser.add_argument(
        "--cache-root",
        type=Path,
        default=DEFAULT_CACHE_ROOT,
        help="缓存下载的源文件的目录 "
        "(默认: tools/cache)。",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help="保存代码片段的目录 (默认: tools/vuln_code)。 "
        "设置为 '-' 以打印到标准输出。",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    output_dir: Optional[Path]
    if args.output and str(args.output) == "-":
        output_dir = None
    else:
        output_dir = args.output

    try:
        projects = get_projects_by_cve(args.cve_id)
    except ValueError as exc:
        print(f"[extractor] {exc}", file=sys.stderr)
        return 1

    success = True
    for project in projects:
        print(f"[extractor] Processing project: {project.project_slug}")
        try:
            entries = load_entries(project.project_slug, args.fix_info)
            dump_snippets(entries, args.sources_root, args.cache_root, output_dir)
        except (ValueError, FileNotFoundError, ConnectionError) as exc:
            print(f"[extractor] Error processing {project.project_slug}: {exc}", file=sys.stderr)
            success = False

    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())

