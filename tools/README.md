# CWE-Bench-Java 分析工具

此目录包含用于辅助分析 CWE-Bench-Java 数据集的实用脚本。这些工具旨在简化数据获取和漏洞代码提取流程。

## 1. CVE 元数据获取器 (`cve_fetcher.py`)

从 NVD REST API v2 获取指定 CVE 的详细元数据（JSON 格式）。

### 功能
- 获取 CVE 描述、评分、CWE 编号等信息。
- 支持使用 API Key 以提高请求速率限制。
- 自动保存为 JSON 文件。

### 用法示例

**基础用法**
```bash
python cve_fetcher.py CVE-2018-8041
```
*输出*: `tools/cve_info/CVE-2018-8041.json`

**使用 API Key**
```bash
# 推荐设置环境变量 NVD_API_KEY，或使用 --api-key 参数
python cve_fetcher.py CVE-2018-8041 --api-key <YOUR_KEY>
```

**指定输出目录**
```bash
python cve_fetcher.py CVE-2018-8041 --output-dir my_cve_data
```

---

## 2. 漏洞代码提取器 (`vuln_function_extractor.py`)

从 GitHub 提取指定 CVE 的**漏洞版本**（Buggy Version）源代码片段。

### 功能特点
- **精准提取**: 基于 `data/fix_info.csv` 中的信息，利用方法名智能定位源代码中的漏洞函数，避免行号错位问题。
- **全面覆盖**: 能够正确处理涉及多个文件或多个方法的复杂漏洞修复，确保提取出完整的漏洞代码片段集合。
- **功能丰富**: 自动获取 CVE 的自然语言描述（来自 NVD），并整合到结果中。
- **自动管理**: 自动下载所需的源代码文件，提取完成后自动清理缓存（默认行为），节省磁盘空间。
- **格式统一**: 输出为结构化的 JSON 文件，包含代码片段、文件路径、CVE ID 等元数据。
- **批量处理**: 支持提取单个 CVE 或批量提取所有记录的 CVE。

### 输出格式
结果保存为 JSON 文件（默认在 `tools/result/` 目录下），包含漏洞代码及 NVD 描述。格式如下：

```json
{
  "cve_id": "CVE-2018-8041",
  "description": "Apache Camel 2.20.0 through 2.20.3... (Vulnerability description from NVD)",
  "projects": [
    {
      "project_slug": "apache__camel_CVE-2018-8041_2.20.3",
      "buggy_commit_id": "32bfda73ddd1ea8576bcb53dac496af9e0825f1a",
      "vuln_snippets": [
        {
          "file_path": "components/camel-mail/src/main/java/org/apache/camel/component/mail/MailBinding.java",
          "class_name": "MailBinding",
          "method_name": "extractAttachmentsFromMultipart",
          "code": "protected void extractAttachmentsFromMultipart(...) { ... }",
          "start_line": 305,
          "end_line": 342,
          "loc_source": "regex" // "regex" (精确匹配) 或 "fix_info_fallback" (回退行号)
        },
        {
           "...": "..." 
           "note": "若该 CVE 涉及多个漏洞位置，此处会有多个代码片段对象"
        }
      ]
    }
  ]
}
```

### 用法示例

**1. 提取单个 CVE**
```bash
python vuln_function_extractor.py CVE-2018-8041
```
*行为*: 下载源码 -> 提取代码 -> 输出到 `tools/result/CVE-2018-8041.json` -> 删除源码缓存。

**2. 提取并保留缓存**
```bash
python vuln_function_extractor.py CVE-2018-8041 --keep-cache
```
*行为*: 提取后**不删除** `tools/cache` 中的源代码，便于后续查看。

**3. 批量提取所有 CVE**
```bash
python vuln_function_extractor.py --all
```
*输出*: `tools/result/all_vuln_data.json`

**4. 指定输出文件路径**
```bash
python vuln_function_extractor.py CVE-2018-8041 --output my_analysis.json
```

**5. 使用本地源代码**
```bash
# 如果你已经克隆了项目代码，可以指定路径以避免下载
python vuln_function_extractor.py CVE-2018-8041 --sources-root D:\projects\CWE-Bench-Java\project-sources
```

### 常用选项
- `--keep-cache`: 提取后保留下载的源代码（默认会删除）。
- `--output <file>`: 指定输出 JSON 文件的路径。
- `--cache-root <dir>`: 指定缓存目录（默认为 `tools/cache`）。
- `--all`: 处理 `data/project_info.csv` 中列出的所有 CVE。
