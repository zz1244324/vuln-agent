import json
import sys
from pathlib import Path

import argparse


sys.stdout.reconfigure(encoding="utf-8")

#audit文件路径,做json处理
def load_audit(path):

    with open(path, encoding="utf-8") as f:
        text = json.load(f)["dependencies"]

    return text

#自家包判断,site_packages为库资源目录
def self_package(site_packages,name,version):
    marker = Path(site_packages) / f"{name}-{version}.dist-info" / "direct_url.json"
    if not marker.exists():
        return False
    with open(marker, encoding="utf-8") as f:
        info = json.load(f)
    return "dir_info" in info
#过滤函数
#deps为load_audit(path)输出文件,site_packages为库资源目录
def filter_audit(deps,site_packages):

    drop=[]
    keep=[]
    for i in deps:
        if i.get("vulns"):
            name=(i.get("name"))
            version=(i.get("version"))
            vuln_id=set()
        
            
            if self_package(site_packages,name,version):
                for j in i.get("vulns"):
                    drop.append({"package": name, "version":version, "vuln_id":j.get("id"),  "reason": "self-package"})
            else:
                for j in i.get("vulns"):
                    if j.get("id") not in vuln_id:
                        keep.append({"package": name,"version":version, "vuln_id":j.get("id")})
                        vuln_id.add(j.get("id"))
                    else:
                        drop.append({"package": name, "version":version, "vuln_id":j.get("id"),  "reason": f"duplicate-of:{j.get('id')}"})

    return keep,drop


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("audit", type=Path, help="pip-audit 输出的 audit.json 路径")
    parser.add_argument("--site-packages", type=Path, required=True, help="被审计项目的 site-packages 目录")
    parser.add_argument("--out", default="filter_results.json", help="输出 JSON 路径")
    args = parser.parse_args()

    keep,drop=filter_audit(load_audit(args.audit),args.site_packages)


    print(f"keep/drop:{len(keep)}/{len(drop)}")
    
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)

    #输出过滤结果文件
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump({"keep": keep, "drop": drop}, f, ensure_ascii=False, indent=2)
