## 效果

对 `sca-lab` 靶场（urllib3 2.0.5 / jinja2 3.1.2 / requests 2.31.0 + 一个撞名的自建包）
跑一遍：

| 包 | 版本 | pip-audit 报 | 保留 | 删除 | 删除理由 |
|----|------|-------------|------|------|---------|
| urllib3  | 2.0.5 | 18 | 10 | 8 | duplicate-of ×8 |
| jinja2   | 3.1.2 | 10 |  5 | 5 | duplicate-of ×5 |
| requests | 2.31.0 |  6 |  3 | 3 | duplicate-of ×3 |
| pyyaml   | 5.3.1 |  2 |  0 | 2 | self-package ×2 |
| 合计     |       | 36 | 18 | 18 | |

### 这两类删除不是一回事

- **duplicate-of（16 条）**：pip-audit 的同一漏洞条目在输出里重复出现
  （`jinja2` 的 10 条里只有 5 个不同 id）。去重治的是输出重复。
- **self-package（2 条）**：`pyyaml` 这个名字恰好撞上 PyPI 上真有的同名包，
  但它是本地自建的。pip-audit 的判据只有"包名 + 版本"，永远分不出这两种，
  **这才是本工具独有的能力**。

### 复现

uv run vuln-agent-filter #pip-audit 输出的 audit.json 路径 
--site-packages #被审计项目的 site-packages 目录
--out #结果存放位置



### 已知边界

- 跨数据源去重（`id ∪ aliases` 求交集）未实现，但本靶场的 18 个 id 的 aliases
  互不相交，一条也没触发到 —— 需接第二个数据源才能验证。
- PyPI 包名归一化（`_` ↔ `-`）未处理，可能导致 dist-info 目录名匹配失败。
