import json
import os
import requests
import time
import sqlite3
from dotenv import load_dotenv
import argparse

load_dotenv()

evidence = {
    "name": "shiro-deser",
    "target": "http://192.168.189.136:8080",
    "detail": "命中词:You have successfully logged in",
    "status_code": 200,
    "family": "反序列化",
    "cve": "CVE-2016-4437",
    "severity_from_tool": "critical",
    "fix_hint": "Shiro 1.2.5 起更换默认密钥；升级并替换 rememberMe 加密 key",
}
FACTS = {   # 模板名: (family, cve, severity, fix_hint)
 "shiro-deser":      ("反序列化",   "CVE-2016-4437", "critical", "升级 Shiro 至 1.2.5+ 并更换 rememberMe 默认 key"),
 "thinkphp5-rce":    ("代码执行",   "CVE-2018-20062", "critical", "升级 ThinkPHP 5.x 至官方修复版本，禁用 invokefunction 路由"),
 "weblogic-ssrf":    ("SSRF",      "CVE-2014-4210", "high", "升级 WebLogic 至 10.3.6+，限制 uddiexplorer 组件访问"),
 "joomla-unauth":    ("未授权访问", "CVE-2023-23752", "high", "升级 Joomla 至 4.2.8+，为 REST API 增加鉴权"),
 "phpunit-rce":      ("代码执行",   "CVE-2017-9841", "critical", "删除 vendor/phpunit 下的 eval-stdin.php 或升级 PHPUnit"),
 "nginx-alias":      ("配置错误",   "无", "high", "修正 alias 目录拼接，使用 root 替代 alias 或加尾斜杠"),
 "tomcat弱口令":      ("默认凭据",   "无", "high", "修改 manager 默认口令，限制 /manager 访问来源"),
 "ssti":             ("SSTI",      "无", "high", "模板中禁止用户输入进入渲染上下文"),
 "ssrf":             ("SSRF",      "无", "high", "限制服务端出站请求目标，禁用用户可控地址"),
 "less9-time-blind": ("SQL注入",   "无", "high", "SQL 使用 ? 占位符，禁用拼接"),
 "less11-post-sqli": ("SQL注入",   "无", "high", "SQL 使用 ? 占位符，禁用拼接"),
 "less11-raw":       ("SQL注入",   "无", "high", "SQL 使用 ? 占位符，禁用拼接"),
 "sqli-error":       ("SQL注入",   "无", "high", "SQL 使用 ? 占位符，禁用拼接"),
 "xff-spoof":        ("配置错误",   "无", "medium", "不信任 X-Forwarded-For，仅记录不用于鉴权"),
 "bak-exposed":      ("配置错误",   "无", "medium", "禁止 Web 目录存放 .bak/.sql/.zip 等备份文件"),
}

def send(evidence):

    resp = requests.post(
        "https://open.bigmodel.cn/api/paas/v4/chat/completions",
        headers={"Authorization": f"Bearer {os.environ['LLM_KEY']}"},
        json={
            "model": "glm-4-flash",
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "你是漏洞报告助手。只输出 JSON，不要 markdown 代码块，不要多余文字。"
                        "字段与规则："
                        "1. vuln_type：用证据里的 family 字段。"
                        "2. severity：必须原样使用证据里的 severity_from_tool，不许自己判断。"
                        "3. explanation：必须引用具体证据——写出 cve 编号，并说明 detail 中的事实如何证明攻击已经成功。禁止写不依赖证据的通用描述"
                        "4. fix：只能依据证据里的 fix_hint 写；没有的信息写'未知'，不许编造。"
                        '''5. verdict 是扫描器给出的结论，你不得推翻。你的任务是用 detail 解释它如何支撑该结论。
                        若 detail 与 verdict 明显矛盾（例如证据其实来自另一种漏洞），
                        explanation 必须以"证据与结论不一致："开头并说明原因。
                        不要输出"证据不足"——结论是否成立不是你的判断范围。
                        '''
                    ),
                },
                {"role": "user", "content": json.dumps(evidence, ensure_ascii=False)},
            ],
            "response_format": {"type": "json_object"},
            "max_tokens": 300,
        },
        timeout=20
    )
    return  resp

def result(evidence):
    for attempt in range(1, 4):
        try:
            resp = send(evidence)
        except (requests.Timeout, requests.RequestException) as e:
            print(f"发生请求错误:{e}")
            if attempt == 3 :

                return {"ok": False, "error": "超时重试3次仍失败", "raw": None}
            time.sleep(attempt)
            continue

        # 走到这里 = 拿到响应了，所有状态码判断都在这
        if resp.status_code in (400, 401, 403):
            return {"ok": False, "error": f"状态{resp.status_code},可能 key 错", "raw": resp.text}
        if resp.status_code in (429, 500, 502, 503, 504):
            if attempt == 3 :
                return {"ok": False, "error": f"状态{resp.status_code}", "raw": resp.text}
            time.sleep(attempt)
            continue
        break
    data=resp.json()
    return {"ok": True, "data":data, "raw": data["choices"][0]["message"]["content"], "tokens": data["usage"]}

def sql_connect(db_path):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT template_name, url, detail, status_code FROM records WHERE status='hit' and detail != '' GROUP BY template_name, url").fetchall()
    conn.row_factory = sqlite3.Row
    conn.close()
    return rows

def build_evidences(rows):
    evs = []
    for r in rows:
        name = r["template_name"]
        if name not in FACTS:
            print(f"跳过 {name}:FACTS 里没有它的事实")
            continue
        family, cve, severity, fix_hint = FACTS[name]     # 四元组解包
        evs.append({
            "name": name,
            "target": r["url"],
            "detail": r["detail"],
            "status_code": r["status_code"],
            "family": family,
            "cve": cve,
            "severity_from_tool": severity,
            "fix_hint": fix_hint,
            "verdict": "hit",
        })
    return evs




def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("db", help="vuln-pocs 的 result.db 路径")
    parser.add_argument("--out", default="llm_results.json", help="输出 JSON 路径")
    args = parser.parse_args()

    rows = sql_connect(args.db)
    evs = build_evidences(rows)
    print(f"读到 {len(rows)} 条，可用 {len(evs)} 条")

    results = []
    ok = fail = 0

    for i, ev in enumerate(evs, 1):
        print(f"[{i}/{len(evs)}] {ev['name']}")
        r = result(ev)
        if r["ok"]:
            ok += 1
            try:
                parsed = json.loads(r["raw"])          # 模型输出解析
            except json.JSONDecodeError:
                parsed = None                          # 解析失败也不毁批
            results.append({"name": ev["name"], "ok": True, "parsed": parsed, "tokens": r["tokens"]})
        else:
            fail += 1
            results.append({"name": ev["name"], "ok": False, "error": r["error"]})

    print(f"成功 {ok} / 失败 {fail}")

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)

