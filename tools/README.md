# 自定义分析工具

此文件夹包含实用脚本，用于在 Windows 或其他环境中补充 CWE-Bench-Java 数据集，以便更方便地进行分析。

## `cve_fetcher.py`

- 从公共 NVD REST API v2 获取指定 CVE ID 的完整元数据。
- 默认情况下，每次运行都会将 JSON 文件写入 `tools/cve_info/<CVE>.json`。使用 `--output-dir` 更改文件夹或使用 `--outfile` 指定完全自定义的路径。
- 功能:
  - 无需 API 密钥即可工作（速率限制较低），也可以通过 CLI 标志或 `NVD_API_KEY` 环境变量使用密钥。
  （echo $env:NVD_API_KEY，可以查看到我已经配置了API）
  - 优雅地处理网络错误和未找到的 CVE。

### 使用示例

**1. 基础用法** (如果已配置 `NVD_API_KEY` 环境变量):
```bash
python cve_fetcher.py CVE-2021-12345
```

**2. 指定输出目录**:
```bash
python cve_fetcher.py CVE-2021-12345 --output-dir my_cve_data
```

**3. 显式指定 API Key**:
```bash
python cve_fetcher.py CVE-2021-12345 --api-key <YOUR_API_KEY>
```

## `vuln_function_extractor.py`

- 读取 `data/fix_info.csv` 和 `data/project_info.csv`，查找与给定 CVE ID 关联的所有项目的记录方法/类范围，并复制易受攻击的函数体。
- **无需完整的仓库克隆** – 只有缺失时才会下载引用的文件（通过 GitHub raw URLs）。您仍然可以通过 `--sources-root` 指向现有的本地代码库。
- 功能:
  - 自动将 CVE ID 映射到项目标识符 (project slugs)。
  - 自动仅获取每个代码片段所需的文件。
  - 默认将代码片段存储在 `tools/vuln_code/<project_slug>/...` 下；传递 `--output <dir>` 以覆盖或 `--output -` 以打印到标准输出。
  - 可选的缓存目录（`--cache-root`，默认为 `tools/cache`）。
  - 当缺少方法范围时回退到类范围。
  - 支持将代码片段转储到文件或打印到标准输出。
  - 专为在 Windows 上运行而设计（无需仅限 Unix 的工具）。

### 使用示例

**1. 基础用法 (提取指定 CVE 的代码)**:
```bash
python vuln_function_extractor.py CVE-2018-8041
```

**2. 指定输出目录**:
```bash
python vuln_function_extractor.py CVE-2018-8041 --output my_vuln_code
```

**3. 打印到控制台 (不保存文件)**:
```bash
python vuln_function_extractor.py CVE-2018-8041 --output -
```
