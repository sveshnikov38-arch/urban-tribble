# scan_urban_tribble.py
import os, re, sys, json, importlib

def read_text(p):
    return open(p, "r", encoding="utf-8", errors="ignore").read()

def find_file(arg_path=None):
    if arg_path and os.path.isfile(arg_path):
        return os.path.abspath(arg_path)
    cand = ["mini_crm.py", "app.py", "main.py"]
    for c in cand:
        if os.path.isfile(c):
            return os.path.abspath(c)
    # иначе ищем самый большой .py в корне
    pys = [f for f in os.listdir(".") if f.endswith(".py")]
    if pys:
        pys.sort(key=lambda n: os.path.getsize(n), reverse=True)
        return os.path.abspath(pys[0])
    return None

def extract_routes(txt):
    routes = []
    lines = txt.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        if "@app.route(" in line:
            deco = line
            # соберём декоратор, если многострочный
            j = i + 1
            while not deco.strip().endswith(")") and j < len(lines):
                deco += "\n" + lines[j]
                j += 1
            # путь
            m = re.search(r"@app\.routeKATEX_INLINE_OPEN\s*([\"'])(.+?)\1", deco)
            path = m.group(2) if m else "?"
            # методы
            mm = re.search(r"methods\s*=\s*```math
([^```]+)```", deco)
            methods = []
            if mm:
                for t in re.findall(r"[\"']([A-Z]+)[\"']", mm.group(1)):
                    methods.append(t)
            # найдём ближайший def
            k = j
            func = "?"
            ln = j+1
            while k < len(lines) and k < j + 10:
                mdef = re.search(r"^\s*def\s+([a-zA-Z_]\w*)\s*KATEX_INLINE_OPEN", lines[k])
                if mdef:
                    func = mdef.group(1)
                    ln = k+1
                    break
                k += 1
            routes.append({"line": ln, "path": path, "methods": methods or ["GET"], "func": func})
            i = j
        i += 1
    return routes

def extract_tables(txt):
    tables = []
    for m in re.finditer(r"CREATE\s+TABLE\s+IF\s+NOT\s+EXISTS\s+([a-zA-Z_]\w*)\s*KATEX_INLINE_OPEN", txt, re.I):
        tables.append(m.group(1))
    return sorted(set(tables))

def extract_alters(txt):
    alters = []
    for m in re.finditer(r"ALTER\s+TABLE\s+([a-zA-Z_]\w*)\s+ADD\s+COLUMN\s+([a-zA-Z_]\w*)", txt, re.I):
        alters.append({"table": m.group(1), "column": m.group(2)})
    return alters

def grep_flags(txt):
    flags = {}
    flags["uses_before_first_request"] = "@app.before_first_request" in txt
    flags["uses_before_request"] = "@app.before_request" in txt
    flags["has_entrypoint"] = ("if __name__ == \"__main__\":" in txt) or ("if __name__ == '__main__':" in txt)
    flags["has_api_task_update_bug"] = bool(re.search(r"return\s+jsonify\s*KATEX_INLINE_OPEN\s*ok\s*KATEX_INLINE_OPEN\s*False\s*KATEX_INLINE_CLOSE", txt))
    flags["has_sse_route"] = ("text/event-stream" in txt) or ("/sse" in txt and "@app.route" in txt)
    flags["sets_csp"] = ("Content-Security-Policy" in txt) or ("csp_nonce" in txt)
    flags["has_csrf_helpers"] = all(s in txt for s in ["ensure_csrf", "verify_csrf", "verify_csrf_header"])
    flags["has_rate_limit"] = "def rate_limit(" in txt
    flags["has_login_lock"] = "def login_locked(" in txt
    flags["has_webhook_worker"] = "def webhook_worker(" in txt
    flags["has_maintenance_worker"] = "def maintenance_worker(" in txt
    flags["has_fts"] = "FTS" in txt or "fts5" in txt.lower()
    flags["has_storage_s3"] = "boto3" in txt
    flags["has_redis"] = "redis" in txt
    flags["has_sentry"] = "sentry_sdk" in txt
    flags["has_magic_sniff"] = "import magic" in txt
    flags["has_ai_endpoints"] = "/api/ai/" in txt
    return flags

def extract_env_vars(txt):
    envs = re.findall(r"os\.environ\.getKATEX_INLINE_OPEN\s*[\"']([A-Z0-9_]+)[\"']", txt)
    return sorted(set(envs))

def detect_flask_version():
    try:
        return importlib.metadata.version("flask")
    except Exception:
        return None

def endpoints_summary(routes, limit=50):
    # агрегируем по базовым префиксам
    buckets = {}
    for r in routes:
        p = r["path"]
        key = p.split("/", 2)[:2]
        key = "/".join(key) if len(key) > 1 else p
        buckets.setdefault(key, 0)
        buckets[key] += 1
    top = sorted(buckets.items(), key=lambda kv: kv[1], reverse=True)[:limit]
    return [{"prefix": k, "count": v} for k, v in top]

def main():
    path = find_file(sys.argv[1] if len(sys.argv) > 1 else None)
    if not path:
        print(json.dumps({"error": "python file not found in current directory"}, ensure_ascii=False))
        return
    txt = read_text(path)
    routes = extract_routes(txt)
    data = {
        "file": path,
        "size_kb": len(txt)//1024,
        "lines": txt.count("\n")+1,
        "flask_version": detect_flask_version(),
        "flags": grep_flags(txt),
        "routes_count": len(routes),
        "routes_prefix_summary": endpoints_summary(routes),
        "tables_count": len(extract_tables(txt)),
        "tables": extract_tables(txt)[:50],
        "alters_count": len(extract_alters(txt)),
        "env_vars_count": len(extract_env_vars(txt)),
        "env_vars_sample": extract_env_vars(txt)[:50],
        "entrypoint_present": grep_flags(txt)["has_entrypoint"],
        "critical_checks": {
            "before_first_request_present": grep_flags(txt)["uses_before_first_request"],
            "api_task_update_bug": grep_flags(txt)["has_api_task_update_bug"]
        },
    }
    # Маркеры-проблемы с координатами (строки)
    markers = []
    for pat, name in [
        (r"@app\.before_first_request", "before_first_request"),
        (r"return\s+jsonify\s*KATEX_INLINE_OPEN\s*ok\s*KATEX_INLINE_OPEN\s*False\s*KATEX_INLINE_CLOSE", "api_task_update_bug"),
    ]:
        for m in re.finditer(pat, txt):
            line = txt[:m.start()].count("\n") + 1
            markers.append({"name": name, "line": line})
    data["markers"] = markers
    # Агрегированная карта роутов (ограниченная)
    data["routes_sample"] = routes[:120]
    print(json.dumps(data, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()
