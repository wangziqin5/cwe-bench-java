"""
提取指定 CVE 的漏洞代码及其详细信息。
从 buggy_commit_id 下载源代码，根据 fix_info.csv 中的方法名定位并提取易受攻击的代码。
输出为一个包含所有相关代码片段和元数据的 JSON 文件。

示例:
    python vuln_function_extractor.py CVE-2018-8041
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
import os
import shutil
import urllib.error
import urllib.request
try:
    import cve_fetcher
except ImportError:
    sys.path.append(str(Path(__file__).resolve().parent))
    import cve_fetcher

from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple, Any

REPO_ROOT = Path(__file__).resolve().parents[1]
FIX_INFO_PATH = REPO_ROOT / "data" / "fix_info.csv"
PROJECT_INFO_PATH = REPO_ROOT / "data" / "project_info.csv"
DEFAULT_CACHE_ROOT = Path(__file__).resolve().parent / "cache"
DEFAULT_OUTPUT_DIR = Path(__file__).resolve().parent / "result"
RAW_GITHUB_BASE = "https://raw.githubusercontent.com"


@dataclass
class FixEntry:
    project_slug: str
    file_path: str
    method: str
    class_name: str
    start_line: int
    end_line: int
    signature: str
    fix_commit_id: str


@dataclass
class ProjectInfo:
    project_slug: str
    cve_id: str
    github_username: str
    github_repository_name: str
    buggy_commit_id: str


PROJECT_INFO_MAP: Dict[str, ProjectInfo] = {}
FIX_INFO_MAP: Dict[str, List[FixEntry]] = {}


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


def load_fix_info(csv_path: Path) -> None:
    """预加载整个 fix_info.csv 到内存"""
    if FIX_INFO_MAP:
        return
    
    if not csv_path.exists():
        raise FileNotFoundError(f"Fix info file not found: {csv_path}")

    seen = set()
    with csv_path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            project_slug = row["project_slug"]
            
            method_name = row.get("method", "").strip()
            class_name = row.get("class", "").strip()
            file_path = row["file"]
            signature = row.get("signature", "").strip()
            fix_commit_id = row.get("commit", "").strip()
            
            # 使用项目、文件、类、方法名作为去重键
            key = (project_slug, file_path, class_name, method_name, signature)
            if key in seen:
                continue
            seen.add(key)
            
            method_start = safe_int(row.get("method_start"))
            method_end = safe_int(row.get("method_end"))
            class_start = safe_int(row.get("class_start"))
            class_end = safe_int(row.get("class_end"))

            start_line = method_start or class_start or 0
            end_line = method_end or class_end or 0

            entry = FixEntry(
                project_slug=project_slug,
                file_path=file_path,
                method=method_name or "<class-scope>",
                class_name=class_name,
                start_line=start_line,
                end_line=end_line,
                signature=signature,
                fix_commit_id=fix_commit_id
            )
            
            if project_slug not in FIX_INFO_MAP:
                FIX_INFO_MAP[project_slug] = []
            FIX_INFO_MAP[project_slug].append(entry)


def get_entries_for_project(project_slug: str) -> List[FixEntry]:
    return FIX_INFO_MAP.get(project_slug, [])


def find_method_by_name(
    source_code: str, 
    method_name: str, 
    class_name: str,
    fallback_start: int = 0,
    fallback_end: int = 0
) -> Optional[Tuple[int, int]]:
    """
    在源代码中通过方法名查找方法的位置（行号范围）。
    返回 (start_line, end_line) 或 None 如果找不到。
    """
    lines = source_code.splitlines()
    
    if not method_name or method_name == "<class-scope>":
        if fallback_start > 0 and fallback_end > 0:
            return (fallback_start, fallback_end)
        return None
    
    escaped_method = re.escape(method_name)
    
    method_patterns = []
    
    # 1. 标准方法定义 (Standard Method Definition)
    method_patterns.append(re.compile(rf'^\s*(?:[\w<>\[\]\.,]+\s+)+{escaped_method}\s*\('))
    
    # 2. 构造函数 (Constructor)
    if method_name == class_name:
        method_patterns.append(re.compile(rf'^\s*(?:public|protected|private)\s+{escaped_method}\s*\('))
        method_patterns.append(re.compile(rf'^\s*{escaped_method}\s*\('))
    
    # 3. 宽松匹配 (Loose Match) - 尝试捕获前面有注解或换行的情况
    # 匹配: (空格) [单词] (空格) method_name (空格) (
    # 例如: " boolean evaluate("
    method_patterns.append(re.compile(rf'\s+[\w<>\[\]]+\s+{escaped_method}\s*\('))

    brace_count = 0
    method_start = None
    found_brace = False
    
    for i, line in enumerate(lines, start=1):
        if method_start is None:
            # 排除明显的方法调用
            if f".{method_name}" in line or f"new {method_name}" in line:
                continue
            # 排除控制流关键字
            if any(keyword in line for keyword in [f"if({method_name}", f"if ({method_name}", f"while({method_name}", f"while ({method_name}"]):
                continue

            for pattern in method_patterns:
                if pattern.search(line):
                    # 额外的检查：如果这行看起来像方法调用
                    # 比如 "return evaluate(b);" -> pattern 3 可能会匹配到 " return evaluate("
                    stripped = line.strip()
                    if stripped.startswith("return ") or stripped.startswith("throw "):
                        continue
                    
                    method_start = i
                    break 
            
            if method_start is None:
                continue

        # 进入方法后的逻辑 (包括找到方法的那一行)
        
        # 1. 尝试寻找起始的大括号 "{"
        if not found_brace:
            if '{' in line:
                found_brace = True
            elif ';' in line:
                # 可能是抽象方法或接口方法定义，直接结束
                if method_start is not None:
                    return (method_start, i)
            
        # 2. 如果已经找到了起始括号
        if found_brace:
            brace_count += line.count('{') - line.count('}')
            if brace_count == 0:
                return (method_start, i)
    
    # 如果遍历完文件还没结束
    if method_start is not None:
        return (method_start, len(lines))
    
    # 没找到方法
    if fallback_start > 0 and fallback_end > 0:
        if fallback_start <= len(lines) and fallback_end <= len(lines):
            return (fallback_start, fallback_end)
    
    return None


def extract_snippet_data(source_file: Path, entry: FixEntry) -> Optional[Dict[str, Any]]:
    """
    读取并提取代码片段及详细信息。
    """
    if not source_file.exists():
        print(f"[extractor] Warning: Source file does not exist: {source_file}", file=sys.stderr)
        return None

    try:
        source_code = source_file.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        print(f"[extractor] Error reading {source_file}: {e}", file=sys.stderr)
        return None

    lines = source_code.splitlines()
    
    method_range = find_method_by_name(
        source_code, 
        entry.method, 
        entry.class_name,
        entry.start_line,
        entry.end_line
    )
    
    if method_range is None:
        # 尝试使用提供的行号范围
        if entry.start_line > 0 and entry.end_line > 0 and entry.end_line <= len(lines):
             method_range = (entry.start_line, entry.end_line)
        else:
            print(f"[extractor] Warning: Could not locate method '{entry.method}' in {entry.file_path}", file=sys.stderr)
            return None
    
    start_line, end_line = method_range
    snippet = "\n".join(lines[start_line - 1 : end_line])
    
    return {
        "file_path": entry.file_path,
        "class_name": entry.class_name,
        "method_name": entry.method,
        "signature": entry.signature,
        "start_line": start_line,
        "end_line": end_line,
        "code": snippet,
        "project_slug": entry.project_slug,
        "fix_commit_id": entry.fix_commit_id
    }


def load_project_info() -> None:
    if PROJECT_INFO_MAP:
        return
    if not PROJECT_INFO_PATH.exists():
        raise FileNotFoundError(f"Project info file not found: {PROJECT_INFO_PATH}")
        
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
    if target_path.exists():
        return target_path

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
        target_path.write_bytes(data)
    except Exception as exc:
        # 如果下载失败，记录警告但不中断整个过程
        print(f"[extractor] Warning: Failed to download {raw_url}: {exc}", file=sys.stderr)
        return target_path # 返回路径，即使文件不存在，后续检查会处理

    return target_path


def resolve_source_file(
    project_slug: str,
    relative_path: str,
    sources_root: Optional[Path],
    cache_root: Path,
) -> Path:
    # 如果提供了本地源代码根目录，优先使用
    if sources_root:
        candidate = sources_root / project_slug / relative_path
        if candidate.exists():
            return candidate

    # 否则使用缓存/下载
    project_info = PROJECT_INFO_MAP.get(project_slug)
    if not project_info:
        raise ValueError(f"Project info not found for {project_slug}")
        
    return download_source_file(project_info, relative_path, cache_root)


def remove_empty_dirs(path: Path, stop_at: Path) -> None:
    try:
        while path != stop_at and path.exists():
            if not any(path.iterdir()):
                path.rmdir()
                path = path.parent
            else:
                break
    except OSError:
        pass


def get_cve_description(cve_id: str) -> str:
    """获取 CVE 的英文描述"""
    # 1. 尝试从本地缓存读取
    cve_info_dir = Path(__file__).resolve().parent / "cve_info"
    cve_file = cve_info_dir / f"{cve_id}.json"
    
    data = None
    if cve_file.exists():
        try:
            with cve_file.open("r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            print(f"[extractor] Warning: Failed to read local CVE info {cve_file}: {e}", file=sys.stderr)
    
    # 2. 如果本地没有或读取失败，尝试在线获取
    if not data:
        try:
            # 使用环境变量中的 key
            api_key = os.getenv("NVD_API_KEY")
            print(f"[extractor] Fetching CVE metadata for {cve_id} from NVD...")
            data = cve_fetcher.fetch_cve(cve_id, api_key=api_key)
            
            # 可选：保存到本地缓存
            cve_info_dir.mkdir(parents=True, exist_ok=True)
            with cve_file.open("w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"[extractor] Warning: Failed to fetch CVE metadata for {cve_id}: {e}", file=sys.stderr)
            return "Description not available."

    # 3. 解析描述
    try:
        # NVD JSON 2.0 结构
        # vulnerabilities -> [0] -> cve -> descriptions -> list -> lang=='en'
        vuln = data.get("vulnerabilities", [])
        if vuln:
            cve_item = vuln[0].get("cve", {})
            descriptions = cve_item.get("descriptions", [])
            for desc in descriptions:
                if desc.get("lang") == "en":
                    return desc.get("value", "")
            # 如果没有 en，返回第一个
            if descriptions:
                return descriptions[0].get("value", "")
    except (IndexError, KeyError, TypeError) as e:
        print(f"[extractor] Warning: Failed to parse description for {cve_id}: {e}", file=sys.stderr)
        
    return "Description not available."


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cve_id", nargs="?", help="Target CVE Identifier (e.g., CVE-2018-8041). Optional if --all is used.")
    parser.add_argument("--all", action="store_true", help="Process all CVEs found in project_info.csv")
    parser.add_argument("--fix-info", type=Path, default=FIX_INFO_PATH, help="Path to fix_info.csv")
    parser.add_argument("--sources-root", type=Path, default=None, help="Local source code root")
    parser.add_argument("--cache-root", type=Path, default=DEFAULT_CACHE_ROOT, help="Cache directory")
    parser.add_argument("--output", type=Path, default=None, help="Output JSON file path")
    parser.add_argument("--keep-cache", action="store_true", help="Do not delete the cache directory after extraction")

    args = parser.parse_args()

    # 加载项目信息以获取所有可用 CVE
    load_project_info()
    # 预加载修复信息
    load_fix_info(args.fix_info)

    target_cve_ids = []
    if args.all:
        target_cve_ids = sorted(list(set(p.cve_id for p in PROJECT_INFO_MAP.values())))
        print(f"[extractor] Batch processing enabled. Found {len(target_cve_ids)} unique CVEs.")
    elif args.cve_id:
        target_cve_ids = [args.cve_id]
    else:
        parser.error("Either a CVE ID or --all must be specified.")

    # 准备结果容器
    # 如果是批处理模式，我们可能生成一个包含列表的 JSON
    # 如果是单 CVE 模式，保持原有结构
    
    final_results = []
    used_cache_files = set()

    for cve_idx, cve_id in enumerate(target_cve_ids, start=1):
        print(f"[extractor] Processing CVE {cve_idx}/{len(target_cve_ids)}: {cve_id}")
        
        try:
            projects = get_projects_by_cve(cve_id)
        except ValueError as exc:
            print(f"[extractor] Warning: {exc}", file=sys.stderr)
            continue

        # 获取描述
        description = get_cve_description(cve_id)

        cve_data = {
            "cve_id": cve_id,
            "description": description,
            "projects": []
        }

        for project in projects:
            print(f"  -> Project: {project.project_slug}")
            
            project_data = {
                "project_slug": project.project_slug,
                "buggy_commit_id": project.buggy_commit_id,
                "vuln_snippets": []
            }
            
            try:
                entries = get_entries_for_project(project.project_slug)
                if not entries:
                    continue

                for entry in entries:
                    source_path = resolve_source_file(
                        entry.project_slug,
                        entry.file_path,
                        args.sources_root,
                        args.cache_root,
                    )
                    
                    # 记录使用的缓存文件以便后续清理
                    if not args.sources_root or not str(source_path).startswith(str(args.sources_root.resolve())):
                        if source_path.exists():
                            used_cache_files.add(source_path)
                    
                    # 即使 resolve_source_file 返回了文件，它可能属于该项目的目录树中
                    # 我们应该记录项目的缓存根目录，以便清理整个项目目录，而不仅仅是单个文件
                    # 否则空目录会残留下来
                    if not args.sources_root:
                        # 假设结构是 cache_root / project_slug / commit_id / ...
                        # 我们想记录 cache_root / project_slug / commit_id 这一层
                        try:
                            # resolve_source_file 返回的是文件的完整路径
                            # 我们需要找到它属于哪个 commit 目录
                            # 路径结构: cache_root/project_slug/buggy_commit_id/file_path
                            # 简单的做法是利用 ProjectInfo 中的信息
                            project_cache_root = args.cache_root / project.project_slug / project.buggy_commit_id
                            if project_cache_root.exists():
                                # 标记这个目录待清理（我们稍后会递归删除）
                                # 但要注意，我们不仅要删除文件，还要删除目录
                                # 现有的逻辑是删除文件，然后 remove_empty_dirs
                                pass 
                        except Exception:
                            pass

                    snippet_data = extract_snippet_data(source_path, entry)
                    if snippet_data:
                        # 添加 cve_id 到每个片段信息中（冗余但方便）
                        snippet_data["cve_id"] = cve_id
                        project_data["vuln_snippets"].append(snippet_data)
                
                if project_data["vuln_snippets"]:
                    cve_data["projects"].append(project_data)

            except Exception as exc:
                print(f"[extractor] Error processing {project.project_slug}: {exc}", file=sys.stderr)
        
        if cve_data["projects"]:
            final_results.append(cve_data)

    # 确定输出路径
    if args.output:
        output_path = args.output
    else:
        default_out_dir = DEFAULT_OUTPUT_DIR
        default_out_dir.mkdir(parents=True, exist_ok=True)
        
        if args.all:
            output_path = default_out_dir / "all_vuln_data.json"
        else:
            output_path = default_out_dir / f"{target_cve_ids[0]}.json"

    # 如果输出是目录
    if output_path.is_dir():
        if args.all:
            output_path = output_path / "all_vuln_data.json"
        else:
            output_path = output_path / f"{target_cve_ids[0]}.json"

    # 写入结果
    print(f"[extractor] Writing results to {output_path}")
    with output_path.open("w", encoding="utf-8") as f:
        # 如果只有一个结果且不是 --all 模式，为了兼容性，解包列表
        # 但如果用户明确要求批量，或者本来就是个列表结构更通用？
        # 为了保持之前单次运行的输出格式不变（是一个 Object），这里做特殊处理
        if not args.all and len(final_results) == 1:
            json.dump(final_results[0], f, indent=2, ensure_ascii=False)
        else:
            json.dump(final_results, f, indent=2, ensure_ascii=False)

    # 清理下载的文件
    if not args.keep_cache:
        print("[extractor] Cleaning up cache directory...")
        if args.cache_root.exists() and args.cache_root.is_dir():
            try:
                # 防止误删用户提供的 sources-root (如果用户把 cache-root 指向了 sources-root)
                if not args.sources_root or args.cache_root.resolve() != args.sources_root.resolve():
                    shutil.rmtree(args.cache_root)
                    print(f"[extractor] Deleted cache directory: {args.cache_root}")
                else:
                    print(f"[extractor] Skipping cache deletion (cache-root is same as sources-root)")
            except OSError as e:
                print(f"[extractor] Warning: Could not delete cache directory {args.cache_root}: {e}", file=sys.stderr)
    else:
        print(f"[extractor] Cache directory kept at: {args.cache_root}")
    
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
