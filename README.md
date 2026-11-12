## 效果

对 `sca-lab` 靶场（urllib3 2.0.5 / jinja2 3.1.2 / requests 2.31.0 + 一个撞名的自建包）
跑一遍：

| 包 | 版本 | pip-audit 报 | 保留 | 删除 | 删除理由 |
|----|------|-------------|------|------|---------|
| urllib3  | 2.0.5  | 18 | 0 | 18 | not-imported ×18 |
| jinja2   | 3.1.2  | 10 | 5 |  5 | duplicate-of ×5 |
| requests | 2.31.0 |  6 | 3 |  3 | duplicate-of ×3 |
| pyyaml   | 5.3.1  |  2 | 0 |  2 | self-package ×2 |
| 合计     |        | 36 | 8 | 28 |  |

### 这三类删除不是一回事

- **not-imported（18 条）**：`urllib3` 装在环境里，但项目源码里没有任何一处
  `import urllib3`。漏洞是真的，只是当前代码路径用不到它。这里只做
  "未显式 import" 的判定，不叫"不可达"——传递依赖仍可能被间接调用。
- **duplicate-of（8 条）**：pip-audit 的同一漏洞条目在输出里重复出现
  （`jinja2` 的 10 条里只有 5 个不同 id）。去重治的是输出重复。
- **self-package（2 条）**：`pyyaml` 这个名字恰好撞上 PyPI 上真有的同名包，
  但它是本地自建的。pip-audit 的判据只有"包名 + 版本"，永远分不出这两种，
  **这才是本工具独有的能力**。

抽核：11-10 已抽核第二刀的 18 条删除，duplicate-of 均对应同包内同 id 的二次出现、
self-package 的 `direct_url.json` 为 `dir_info.editable`，误删 0；11-12 新增的
not-imported 18 条全部来自 `urllib3` 一个包，源码中搜不到 `import urllib3`。

### 复现

```bash
uv run vuln-agent-filter <audit.json 路径> --site-packages <site-packages 目录> --source <项目根目录> --out <输出文件地址>
```

`--source` 指项目根目录（`.venv` 所在的那一层），扫描时会自动跳过
`.venv` / `site-packages` / `__pycache__` 等目录。




### 已知边界

- 跨数据源去重（`id ∪ aliases` 求交集）未实现，但本靶场的 18 个 id 的 aliases
  互不相交，一条也没触发到 —— 需接第二个数据源才能验证。
- PyPI 包名归一化（`_` ↔ `-`）未处理，可能导致 dist-info 目录名匹配失败。
