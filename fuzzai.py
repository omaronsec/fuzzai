#!/usr/bin/env python3

import argparse
import subprocess
import json
import os
import sys
import time
import tempfile
import requests
import re
from urllib.parse import urlparse
from collections import Counter
from bs4 import BeautifulSoup
from datetime import datetime

# ─────────────────────────────────────────
#  CONFIG  (overridden by CLI args in main)
# ─────────────────────────────────────────
WORDLISTS_DIR = "/root/wordlists"
RESULTS_DIR   = "/root/fuzzai/results"
PROMPTS_DIR   = "/root/fuzzai/prompts"
FFUF_BIN      = "ffuf"
FFUF_THREADS  = 40
FFUF_TIMEOUT  = 10
SAMPLE_RATIO  = 0.20
MAX_DEPTH     = 3
MAX_AI_CALLS  = 50   # per domain, overridden by --ai-budget

# Extensions/filenames that are always interesting — skip AI classification
SENSITIVE_EXTENSIONS = {
    '.zip', '.tar', '.tar.gz', '.tgz', '.gz', '.bz2', '.7z', '.rar',
    '.sql', '.db', '.sqlite', '.dump', '.mdb',
    '.env', '.bak', '.old', '.backup', '.orig', '.save',
    '.pem', '.key', '.p12', '.pfx', '.crt', '.cer',
    '.log',
    '.htpasswd',
}
SENSITIVE_FILENAMES = {
    '.env', 'wp-config.php', 'database.yml', '.htpasswd',
    'config.php', 'settings.py', 'application.properties',
    'secrets.yml', 'credentials.json',
}

# Deterministic severity — these never need AI to judge
EXTENSION_AUTO_SEVERITY = {
    '.env':      ('critical', 'Exposed Environment File'),
    '.pem':      ('critical', 'Exposed Private Key'),
    '.key':      ('critical', 'Exposed Private Key'),
    '.p12':      ('critical', 'Exposed Certificate Bundle'),
    '.pfx':      ('critical', 'Exposed Certificate Bundle'),
    '.sql':      ('critical', 'Exposed Database Dump'),
    '.dump':     ('critical', 'Exposed Database Dump'),
    '.htpasswd': ('critical', 'Exposed Password File'),
    '.db':       ('high',     'Exposed Database File'),
    '.sqlite':   ('high',     'Exposed Database File'),
    '.mdb':      ('high',     'Exposed Database File'),
    '.zip':      ('high',     'Exposed Archive File'),
    '.7z':       ('high',     'Exposed Archive File'),
    '.rar':      ('high',     'Exposed Archive File'),
    '.tar':      ('high',     'Exposed Archive File'),
    '.tar.gz':   ('high',     'Exposed Archive File'),
    '.tgz':      ('high',     'Exposed Archive File'),
    '.bak':      ('high',     'Exposed Backup File'),
    '.backup':   ('high',     'Exposed Backup File'),
    '.gz':       ('medium',   'Exposed Compressed File'),
    '.bz2':      ('medium',   'Exposed Compressed File'),
    '.old':      ('medium',   'Exposed Old File'),
    '.orig':     ('medium',   'Exposed Original File'),
    '.save':     ('medium',   'Exposed Saved File'),
    '.log':      ('medium',   'Exposed Log File'),
    '.crt':      ('medium',   'Exposed Certificate'),
    '.cer':      ('medium',   'Exposed Certificate'),
}
FILENAME_AUTO_SEVERITY = {
    '.env':                    ('critical', 'Exposed Environment File'),
    'wp-config.php':           ('critical', 'Exposed WordPress Config'),
    'database.yml':            ('critical', 'Exposed Database Config'),
    '.htpasswd':               ('critical', 'Exposed Password File'),
    'secrets.yml':             ('critical', 'Exposed Secrets File'),
    'credentials.json':        ('critical', 'Exposed Credentials File'),
    'config.php':              ('high',     'Exposed PHP Config'),
    'settings.py':             ('high',     'Exposed Django Settings'),
    'application.properties':  ('high',     'Exposed Spring Config'),
}

# ─────────────────────────────────────────
#  AI BUDGET  (reset per domain in main)
# ─────────────────────────────────────────
_ai_budget = {"calls": 0, "max": MAX_AI_CALLS, "domain": ""}


class BudgetExhausted(Exception):
    """Raised when per-domain AI call budget is exceeded."""
    pass


# ─────────────────────────────────────────
#  DOMAIN LOGGER
# ─────────────────────────────────────────
class DomainLogger:
    def __init__(self, domain_dir):
        log_path = os.path.join(domain_dir, "run.log")
        self._f = open(log_path, 'a')
        self._f.write(f"\n{'='*60}\n[{datetime.now().isoformat()}] RUN START\n{'='*60}\n")
        self._f.flush()

    def log(self, msg):
        ts = datetime.now().strftime("%H:%M:%S")
        self._f.write(f"[{ts}] {msg}\n")
        self._f.flush()

    def close(self):
        self._f.write(f"[{datetime.now().strftime('%H:%M:%S')}] RUN END\n")
        self._f.close()


# ─────────────────────────────────────────
#  AI BRAIN
# ─────────────────────────────────────────
def ask_ai(prompt, ai="claude", retries=3):
    """Call claude or codex CLI subprocess."""
    _ai_budget["calls"] += 1
    if _ai_budget["calls"] > _ai_budget["max"]:
        raise BudgetExhausted(
            f"AI budget exhausted ({_ai_budget['max']} calls) for {_ai_budget['domain']}"
        )

    for attempt in range(retries):
        try:
            cmd = ["claude", "-p", prompt] if ai == "claude" else ["codex", prompt]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

            combined = (result.stdout + result.stderr).lower()
            if any(x in combined for x in ["rate limit", "too many requests", "quota", "retry after"]):
                wait = _parse_rate_limit_wait(result.stderr or result.stdout, ai)
                print(f"[~] Rate limited. Sleeping {wait}s ...")
                time.sleep(wait)
                continue

            if result.returncode != 0 and not result.stdout.strip():
                raise RuntimeError(f"AI error: {result.stderr.strip()}")

            return result.stdout.strip()

        except subprocess.TimeoutExpired:
            print(f"[!] AI timeout (attempt {attempt+1}/{retries})")
            time.sleep(10)

    raise RuntimeError("AI failed after all retries")


def _parse_rate_limit_wait(error_msg, ai):
    try:
        prompt = open(os.path.join(PROMPTS_DIR, "rate_limit_recovery.prompt")).read()
        prompt = prompt.replace("{error_message}", error_msg)
        out = ask_ai(prompt, ai=ai, retries=1)
        return int(extract_json(out).get("wait_seconds", 300))
    except Exception:
        return 300


def load_prompt(name, **kwargs):
    path = os.path.join(PROMPTS_DIR, name)
    content = open(path).read()
    for key, val in kwargs.items():
        content = content.replace("{" + key + "}", str(val))
    return content


def extract_json(text):
    """Extract first valid JSON object from AI response."""
    try:
        return json.loads(text)
    except Exception:
        pass
    match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except Exception:
            pass
    start = text.find('{')
    end   = text.rfind('}') + 1
    if start != -1 and end > start:
        try:
            return json.loads(text[start:end])
        except Exception:
            pass
    raise ValueError(f"No JSON found in AI response: {text[:300]}")


def validate_ai_json(data, required_keys):
    """Raise if required keys are missing from AI response."""
    missing = [k for k in required_keys if k not in data]
    if missing:
        raise ValueError(f"AI response missing keys: {missing} — got: {list(data.keys())}")
    return data


# ─────────────────────────────────────────
#  HTTP HELPERS
# ─────────────────────────────────────────
def fetch_target(url):
    try:
        r = requests.get(url, timeout=10, allow_redirects=True,
                         headers={"User-Agent": "Mozilla/5.0"})
        soup = BeautifulSoup(r.content, 'html.parser')
        for tag in soup(["script", "style", "img", "svg"]):
            tag.decompose()
        content = soup.get_text(separator=' ', strip=True)[:3000]
        return dict(r.headers), content, r.status_code
    except Exception:
        return {}, "", 0


def fetch_headers(url):
    """Fetch real response headers for a path."""
    try:
        r = requests.head(url, timeout=5, allow_redirects=False,
                          headers={"User-Agent": "Mozilla/5.0"})
        return dict(r.headers), r.headers.get("Location", "")
    except Exception:
        return {}, ""


def is_blocked(results, errors, stderr=""):
    """Detect WAF/rate-limit blocking from ffuf results."""
    if errors > 10:
        return True
    if stderr:
        block_patterns = ["cloudflare", "captcha", "access denied", "waf", "blocked",
                          "rate limit", "too many requests", "forbidden by policy"]
        if any(p in stderr.lower() for p in block_patterns):
            return True
    if not results:
        return False
    statuses = [r["status"] for r in results[:20]]
    if statuses and all(s in [429, 503, 0] for s in statuses):
        return True
    return False


def is_sensitive_by_extension(path):
    """Deterministically flag paths with sensitive extensions — no AI needed."""
    p = path.lower().split('?')[0]
    for ext in SENSITIVE_EXTENSIONS:
        if p.endswith(ext):
            return True
    filename = p.rstrip('/').split('/')[-1]
    return filename in SENSITIVE_FILENAMES


def get_auto_severity(path):
    """Return (severity, title) for known-sensitive paths — no AI call needed.
    Returns (None, None) if path requires AI judgment.
    """
    p = path.lower().split('?')[0]
    filename = p.rstrip('/').split('/')[-1]
    if filename in FILENAME_AUTO_SEVERITY:
        return FILENAME_AUTO_SEVERITY[filename]
    for ext, val in EXTENSION_AUTO_SEVERITY.items():
        if p.endswith(ext):
            return val
    return None, None


# ─────────────────────────────────────────
#  STATE MANAGEMENT
# ─────────────────────────────────────────
def load_state(results_dir):
    state_file = os.path.join(results_dir, "state.json")
    if os.path.exists(state_file):
        with open(state_file) as f:
            return json.load(f)
    return {"completed": [], "queue": [], "current": None}


def save_state(state, results_dir):
    state_file = os.path.join(results_dir, "state.json")
    with open(state_file, 'w') as f:
        json.dump(state, f, indent=2)


def save_finding(finding, domain_dir):
    """Append finding to domain findings.json immediately — deduped by URL."""
    findings_file = os.path.join(domain_dir, "findings.json")
    existing = []
    if os.path.exists(findings_file):
        try:
            with open(findings_file) as f:
                existing = json.load(f)
        except Exception:
            pass
    if finding.get("url") in {f.get("url") for f in existing}:
        return
    existing.append(finding)
    with open(findings_file, 'w') as f:
        json.dump(existing, f, indent=2)


# ─────────────────────────────────────────
#  FFUF RUNNER  (JSON output mode)
# ─────────────────────────────────────────
def count_wordlist_lines(wordlist):
    try:
        result = subprocess.run(["wc", "-l", wordlist], capture_output=True, text=True)
        return int(result.stdout.strip().split()[0])
    except Exception:
        return 10000


def run_ffuf(url, wordlist, extra_flags=None, threads=None, timeout_per_run=600):
    """Run ffuf and return (results, error_count, stderr).
    results: list of dicts — path, status, size, words, lines, url
    """
    t = str(threads or FFUF_THREADS)

    with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as tf:
        out_file = tf.name

    cmd = [
        FFUF_BIN,
        "-u", url,
        "-w", wordlist,
        "-t", t,
        "-timeout", str(FFUF_TIMEOUT),
        "-mc", "200,201,204,301,302,307,401,403,405,500",
        "-o", out_file,
        "-of", "json",
        "-s"
    ]
    if extra_flags:
        cmd += extra_flags

    results     = []
    error_count = 0
    stderr_out  = ""

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        _, stderr_out = proc.communicate(timeout=timeout_per_run)

        if os.path.exists(out_file):
            try:
                with open(out_file) as f:
                    data = json.load(f)
                for r in data.get("results", []):
                    results.append({
                        "path":   r.get("input", {}).get("FUZZ", ""),
                        "status": r.get("status", 0),
                        "size":   r.get("length", 0),
                        "words":  r.get("words", 0),
                        "lines":  r.get("lines", 0),
                        "url":    r.get("url", "")
                    })
            except Exception:
                pass

        for sline in stderr_out.splitlines():
            if re.search(r'error|failed|refused|timeout', sline, re.I):
                error_count += 1

    except subprocess.TimeoutExpired:
        proc.kill()
    finally:
        if os.path.exists(out_file):
            os.unlink(out_file)

    return results, error_count, stderr_out


def run_ffuf_sampled(url, wordlist, sample_ratio=0.20, extra_flags=None, threads=None):
    """Run ffuf on first N% of wordlist."""
    total = count_wordlist_lines(wordlist)
    sample_size = max(50, int(total * sample_ratio))

    tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
    count = 0
    with open(wordlist) as wf:
        for line in wf:
            if count >= sample_size:
                break
            tmp.write(line)
            count += 1
    tmp.close()

    try:
        results, errors, stderr = run_ffuf(url, tmp.name, extra_flags=extra_flags, threads=threads)
    finally:
        if os.path.exists(tmp.name):
            os.unlink(tmp.name)
    return results, errors, total, stderr


def results_to_text(results):
    """Convert result dicts to text lines for AI prompts and raw output files."""
    lines = []
    for r in results:
        lines.append(
            f"{r['path']} [Status: {r['status']}, Size: {r['size']}, "
            f"Words: {r['words']}, Lines: {r['lines']}]"
        )
    return "\n".join(lines)


# ─────────────────────────────────────────
#  AI DECISION FUNCTIONS
# ─────────────────────────────────────────
def tech_detect(url, ai):
    headers, content, _ = fetch_target(url)
    prompt = load_prompt("tech_detect.prompt",
                         url=url, headers=json.dumps(headers), content=content)
    out = ask_ai(prompt, ai=ai)
    data = extract_json(out)
    validate_ai_json(data, ["primary_wordlist"])
    return data


def analyze_and_filter(url, results, ai):
    results_text = results_to_text(results[:200])
    prompt = load_prompt("filter_analysis.prompt", url=url, results=results_text)
    out = ask_ai(prompt, ai=ai)
    data = extract_json(out)
    try:
        validate_ai_json(data, ["filter_command"])
    except ValueError:
        data["filter_command"] = ""
    filter_cmd = data.get("filter_command", "")
    # Whitelist-only flag parsing — no shell injection from AI output
    allowed_flags = {"-fs", "-fw", "-fl", "-fc", "-fr", "-mc"}
    raw_flags = filter_cmd.split() if filter_cmd else []
    flags = []
    i = 0
    while i < len(raw_flags):
        if raw_flags[i] in allowed_flags and i + 1 < len(raw_flags):
            val = raw_flags[i + 1]
            if re.match(r'^[\d,]+$', val):
                flags += [raw_flags[i], val]
            i += 2
        else:
            i += 1
    return flags, data


def classify_path(url, path, status, size, words, resp_headers, redirect, ai):
    prompt = load_prompt("path_classifier.prompt",
                         url=url, path=path, status=status,
                         size=size, words=words,
                         headers=json.dumps(resp_headers),
                         redirect=redirect or "")
    out = ask_ai(prompt, ai=ai)
    data = extract_json(out)
    validate_ai_json(data, ["action"])
    return data


def generate_param_wordlist(url, endpoint, tech, status, resp_headers, ai):
    prompt = load_prompt("param_wordlist.prompt",
                         url=url, endpoint=endpoint,
                         tech=json.dumps(tech), status=status,
                         headers=json.dumps(resp_headers))
    out = ask_ai(prompt, ai=ai)
    data = extract_json(out)
    try:
        validate_ai_json(data, ["param_list"])
    except ValueError:
        data["param_list"] = []
    params = data.get("param_list", [])
    if not isinstance(params, list):
        params = []
    if not params:
        return f"{WORDLISTS_DIR}/parameters/burp-parameter-names.txt", data, False

    tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
    for p in params:
        tmp.write(p.strip() + "\n")
    tmp.close()
    return tmp.name, data, True


def judge_finding(finding, status, size, response_snippet, tech, domain, ai):
    prompt = load_prompt("findings_judge.prompt",
                         finding=finding, status=status, size=size,
                         response_snippet=response_snippet[:500],
                         tech=json.dumps(tech), domain=domain)
    out = ask_ai(prompt, ai=ai)
    data = extract_json(out)
    validate_ai_json(data, ["worth_reporting", "severity"])
    return data


def _merge_filter_flags(base, ai):
    """Merge two ffuf flag lists, combining -fs values into one comma-separated list."""
    combined = {}
    for flags in [base, ai]:
        i = 0
        while i < len(flags):
            if flags[i] in {"-fs", "-fw", "-fl", "-fc"} and i + 1 < len(flags):
                key = flags[i]
                vals = set(flags[i+1].split(','))
                combined.setdefault(key, set()).update(vals)
                i += 2
            else:
                i += 1
    result = []
    for flag, vals in combined.items():
        result += [flag, ",".join(sorted(vals))]
    return result


# ─────────────────────────────────────────
#  DOMAIN FUZZER
# ─────────────────────────────────────────
def fuzz_url(target_url, ai, domain_dir, state, depth=0, tech=None,
             filter_flags=None, threads=None, _visited=None, logger=None):
    """
    Recursive fuzzer for a single URL level.
    Returns list of findings.
    _visited: in-memory set for recursion dedup — never persisted to state.
    """
    def log(msg):
        print(msg)
        if logger:
            logger.log(msg)

    if depth > MAX_DEPTH:
        return []

    if _visited is None:
        _visited = set()

    findings = []
    parsed   = urlparse(target_url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    fuzz_target = target_url.rstrip('/') + "/FUZZ"

    if fuzz_target in _visited:
        log(f"{'  '*depth}[~] Already visited: {fuzz_target} — skip")
        return []
    _visited.add(fuzz_target)

    indent = "  " * depth
    log(f"\n{indent}[+] Fuzzing depth {depth}: {target_url}")

    # ── Tech detect (only at depth 0)
    if tech is None:
        try:
            tech = tech_detect(target_url, ai)
            log(f"{indent}[*] Tech: {tech.get('technologies')} → {tech.get('primary_wordlist')}")
        except BudgetExhausted:
            raise
        except Exception as e:
            log(f"{indent}[!] Tech detect failed ({e}) — using default wordlist")
            tech = {"primary_wordlist": f"{WORDLISTS_DIR}/general/onelistforallmicro.txt"}

    wordlist = tech.get("primary_wordlist", f"{WORDLISTS_DIR}/general/onelistforallmicro.txt")
    if not os.path.exists(wordlist):
        log(f"{indent}[!] Wordlist not found: {wordlist} — using default")
        wordlist = f"{WORDLISTS_DIR}/general/onelistforallmicro.txt"

    # ── 20% sample
    log(f"{indent}[*] 20% sample run ...")
    sample_results, errors, total, stderr = run_ffuf_sampled(
        fuzz_target, wordlist, SAMPLE_RATIO, threads=threads
    )

    # WAF check
    if is_blocked(sample_results, errors, stderr):
        log(f"{indent}[!] Possible block detected. Retrying slow (-t 5 -p 1-3) ...")
        sample_results, errors, total, stderr = run_ffuf_sampled(
            fuzz_target, wordlist, SAMPLE_RATIO,
            extra_flags=["-p", "1-3"], threads=5
        )
        if is_blocked(sample_results, errors, stderr):
            log(f"{indent}[!] Still blocked — skipping {target_url}")
            return []

    log(f"{indent}[*] Sample: {len(sample_results)} hits from ~{int(total*SAMPLE_RATIO)} reqs")

    # ── Deterministic pre-filters (always applied, no AI needed)
    # 302 with size 0 = redirect to nowhere, pure noise — always filter
    # 302 with size 0 is the most common false positive pattern
    base_filters = []
    sizes_in_sample = [r["size"] for r in sample_results]
    if sizes_in_sample:
                size_counts = Counter(sizes_in_sample)
        # Any size appearing on >30% of results is a catch-all — filter it
        threshold = max(5, int(len(sample_results) * 0.30))
        noisy_sizes = [str(s) for s, c in size_counts.items() if c >= threshold and s != 0]
        if noisy_sizes:
            base_filters += ["-fs", ",".join(noisy_sizes)]
            log(f"{indent}[*] Auto-filter noisy sizes: {','.join(noisy_sizes)}")
    # Always filter size 0 (302 redirects to nowhere)
    if any(r["size"] == 0 for r in sample_results):
        if "-fs" in base_filters:
            idx = base_filters.index("-fs")
            base_filters[idx + 1] = base_filters[idx + 1] + ",0"
        else:
            base_filters += ["-fs", "0"]
        log(f"{indent}[*] Auto-filter size 0 (empty redirects)")

    # ── AI Filter analysis
    if filter_flags is None:
        filter_flags = list(base_filters)
        if sample_results:
            try:
                ai_flags, fdata = analyze_and_filter(target_url, sample_results, ai)
                # Merge AI flags with base filters, avoid duplicate -fs
                filter_flags = _merge_filter_flags(base_filters, ai_flags)
                log(f"{indent}[*] Filters: {' '.join(filter_flags) or 'none'}")
                if fdata.get("real_findings"):
                    log(f"{indent}[*] Spotted in sample: {fdata['real_findings']}")
            except BudgetExhausted:
                raise
            except Exception as e:
                log(f"{indent}[!] Filter analysis failed ({e}) — using base filters only")

    # ── Full run with filters
    log(f"{indent}[*] Full run with filters ...")
    full_results, _, _ = run_ffuf(fuzz_target, wordlist, extra_flags=filter_flags, threads=threads)

    # ── Sensitive wordlist pass
    sensitive_wl = f"{WORDLISTS_DIR}/sensitive/sensitive-combined.txt"
    if os.path.exists(sensitive_wl):
        log(f"{indent}[*] Sensitive wordlist pass ...")
        sens_results, _, _ = run_ffuf(fuzz_target, sensitive_wl, extra_flags=filter_flags, threads=threads)
        full_results += sens_results

    # Deduplicate by path
    seen_paths = set()
    unique_results = []
    for r in full_results:
        if r["path"] and r["path"] not in seen_paths:
            seen_paths.add(r["path"])
            unique_results.append(r)

    # Save raw output
    raw_file = os.path.join(domain_dir, f"raw_depth{depth}.txt")
    with open(raw_file, 'w') as f:
        f.write(results_to_text(unique_results))
    log(f"{indent}[*] {len(unique_results)} unique results → {raw_file}")

    # ── Classify and act on each result
    for r in unique_results:
        path   = r["path"]
        status = r["status"]
        size   = r["size"]
        words  = r["words"]
        full_url = base_url + "/" + path.lstrip("/")

        try:
            resp_headers, redirect = fetch_headers(full_url)

            # Deterministic extension check — no AI call needed
            if is_sensitive_by_extension(path):
                action = "interesting_file"
                log(f"{indent}  → {path} [{status}] = interesting_file (extension — no AI used)")
            else:
                classification = classify_path(
                    base_url, path, status, size, words, resp_headers, redirect, ai
                )
                action   = classification.get("action", "skip")
                priority = classification.get("priority", "low")
                reason   = classification.get("reason", "")
                log(f"{indent}  → {path} [{status}] = {action} ({priority}) | {reason}")

            # ── interesting_file
            if action == "interesting_file":
                auto_sev, auto_title = get_auto_severity(path)

                if auto_sev:
                    # Known-sensitive extension — no AI needed, severity is deterministic
                    finding = {
                        "url":         full_url,
                        "path":        path,
                        "status":      status,
                        "size":        size,
                        "severity":    auto_sev,
                        "title":       auto_title,
                        "description": f"Sensitive file publicly accessible at {path}",
                        "impact":      f"{auto_title} exposed without authentication",
                        "steps":       [f"GET {path}"]
                    }
                    findings.append(finding)
                    save_finding(finding, domain_dir)
                    log(f"{indent}  [!!!] FINDING [{auto_sev.upper()}]: {auto_title} (auto-detected, no AI used)")
                else:
                    # Unknown extension — use AI to judge
                    snippet = ""
                    try:
                        resp = requests.get(full_url, timeout=10,
                                            headers={"User-Agent": "Mozilla/5.0"})
                        snippet = resp.text[:500]
                    except Exception:
                        pass

                    try:
                        judgment = judge_finding(path, status, size, snippet, tech,
                                                 parsed.netloc, ai)
                    except BudgetExhausted:
                        raise
                    except Exception as e:
                        log(f"{indent}  [!] Judge failed ({e}) — skipping")
                        continue

                    if judgment.get("worth_reporting"):
                        sev = judgment.get("severity", "info")
                        finding = {
                            "url":         full_url,
                            "path":        path,
                            "status":      status,
                            "size":        size,
                            "severity":    sev,
                            "title":       judgment.get("title", path),
                            "description": judgment.get("description", ""),
                            "impact":      judgment.get("impact", ""),
                            "steps":       judgment.get("steps", [])
                        }
                        findings.append(finding)
                        save_finding(finding, domain_dir)
                        log(f"{indent}  [!!!] FINDING [{sev.upper()}]: {finding['title']}")

            # ── go_deeper
            elif action == "go_deeper" and depth < MAX_DEPTH:
                sub_url = base_url + "/" + path.lstrip("/").rstrip("/")
                log(f"{indent}  [>] Recursing into: {sub_url}")
                sub_findings = fuzz_url(
                    sub_url, ai, domain_dir, state,
                    depth=depth + 1, tech=tech, filter_flags=filter_flags,
                    threads=threads, _visited=_visited, logger=logger
                )
                findings.extend(sub_findings)

            # ── param_fuzz
            elif action == "param_fuzz":
                param_file, param_data, is_temp = generate_param_wordlist(
                    base_url, path, tech, status, resp_headers, ai
                )
                total_params = param_data.get("total_params", "?")
                log(f"{indent}  [*] Param fuzzing {path} ({total_params} params) ...")

                try:
                    # Pass 1: find what params exist
                    p1_results, _, _ = run_ffuf(
                        full_url + "?FUZZ=testvalue", param_file,
                        extra_flags=filter_flags, threads=threads
                    )
                    # Pass 2: find file-read params
                    p2_results, _, _ = run_ffuf(
                        full_url + "?FUZZ=../../etc/passwd", param_file,
                        extra_flags=["-mr", "root:x:"], threads=threads
                    )

                    tagged = ([(r, "testvalue") for r in p1_results] +
                              [(r, "../../etc/passwd") for r in p2_results])

                    # Parse baseline sizes from filter flags
                    baseline_sizes = set()
                    for m in re.finditer(r'-fs\s+([\d,]+)', " ".join(filter_flags)):
                        for val in m.group(1).split(','):
                            try:
                                baseline_sizes.add(int(val.strip()))
                            except ValueError:
                                pass

                    seen_params = set()
                    for pr, test_val in tagged:
                        param_name = pr["path"]
                        if not param_name or param_name in seen_params:
                            continue
                        seen_params.add(param_name)

                        if baseline_sizes and pr["size"] in baseline_sizes:
                            continue

                        param_path = f"{path}?{param_name}={test_val}"

                        try:
                            psnippet = ""
                            try:
                                resp = requests.get(
                                    f"{full_url}?{param_name}={test_val}",
                                    timeout=8, headers={"User-Agent": "Mozilla/5.0"}
                                )
                                psnippet = resp.text[:300]
                            except Exception:
                                pass

                            pjudge = judge_finding(param_path, pr["status"], pr["size"],
                                                   psnippet, tech, parsed.netloc, ai)
                            if pjudge.get("worth_reporting"):
                                pfinding = {
                                    "url":         base_url + "/" + param_path.lstrip("/"),
                                    "path":        param_path,
                                    "status":      pr["status"],
                                    "size":        pr["size"],
                                    "severity":    pjudge.get("severity", "medium"),
                                    "title":       pjudge.get("title", f"Parameter: {param_name}"),
                                    "description": pjudge.get("description", ""),
                                    "impact":      pjudge.get("impact", ""),
                                    "steps":       pjudge.get("steps", [])
                                }
                                findings.append(pfinding)
                                save_finding(pfinding, domain_dir)
                                log(f"{indent}  [!!!] PARAM [{pfinding['severity'].upper()}]: {pfinding['title']}")
                        except BudgetExhausted:
                            raise
                        except Exception as e:
                            log(f"{indent}  [!] Param judge failed ({e})")

                finally:
                    if is_temp and os.path.exists(param_file):
                        os.unlink(param_file)

        except BudgetExhausted:
            raise
        except Exception as e:
            log(f"{indent}  [!] Error on {path}: {e}")
            continue

    return findings


# ─────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────
def main():
    global FFUF_THREADS, MAX_DEPTH, MAX_AI_CALLS
    parser = argparse.ArgumentParser(
        description="fuzzai — AI-powered web fuzzer for file & param discovery"
    )
    parser.add_argument("-u", "--url",      help="Single target URL")
    parser.add_argument("-l", "--list",     help="File with list of URLs/domains")
    parser.add_argument("--ai",             choices=["claude", "codex"], default="claude",
                        help="AI provider (default: claude)")
    parser.add_argument("--threads",        type=int, default=FFUF_THREADS,
                        help=f"ffuf threads (default: {FFUF_THREADS})")
    parser.add_argument("--depth",          type=int, default=MAX_DEPTH,
                        help=f"Max recursion depth (default: {MAX_DEPTH})")
    parser.add_argument("--output",         default=RESULTS_DIR,
                        help=f"Output dir (default: {RESULTS_DIR})")
    parser.add_argument("--ai-budget",      type=int, default=MAX_AI_CALLS,
                        help=f"Max AI calls per domain (default: {MAX_AI_CALLS})")
    args = parser.parse_args()

    if not args.url and not args.list:
        parser.print_help()
        sys.exit(1)

    FFUF_THREADS = args.threads
    MAX_DEPTH    = args.depth
    MAX_AI_CALLS = args.ai_budget

    domains = []
    if args.url:
        url = args.url if args.url.startswith("http") else "https://" + args.url
        domains.append(url)
    if args.list:
        with open(args.list) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    if not line.startswith("http"):
                        line = "https://" + line
                    domains.append(line)

    os.makedirs(args.output, exist_ok=True)
    state = load_state(args.output)

    if not state["queue"]:
        state["queue"] = [d for d in domains if d not in state["completed"]]
    else:
        existing = set(state["queue"]) | set(state["completed"])
        for d in domains:
            if d not in existing:
                state["queue"].append(d)

    save_state(state, args.output)

    print(f"[*] fuzzai | AI: {args.ai} | Threads: {args.threads} | Depth: {args.depth} | AI budget: {args.ai_budget}/domain")
    print(f"[*] Queue: {len(state['queue'])} domains | Completed: {len(state['completed'])}")
    print(f"[*] Output: {args.output}")

    # Reload findings from already-completed domains (resume safety)
    all_findings = []
    for completed_url in state.get("completed", []):
        d_name = urlparse(completed_url).netloc.replace(".", "_").replace(":", "_")
        d_findings = os.path.join(args.output, d_name, "findings.json")
        if os.path.exists(d_findings):
            try:
                with open(d_findings) as f:
                    all_findings.extend(json.load(f))
            except Exception:
                pass
    if all_findings:
        print(f"[*] Resuming — reloaded {len(all_findings)} findings from previous runs")

    while state["queue"]:
        domain_url = state["queue"].pop(0)
        state["current"] = domain_url
        save_state(state, args.output)

        domain_name = urlparse(domain_url).netloc.replace(".", "_").replace(":", "_")
        domain_dir  = os.path.join(args.output, domain_name)
        os.makedirs(domain_dir, exist_ok=True)

        print(f"\n{'='*60}")
        print(f"[*] TARGET: {domain_url}")
        print(f"{'='*60}")

        # Reset AI budget for this domain
        _ai_budget["calls"]  = 0
        _ai_budget["max"]    = args.ai_budget
        _ai_budget["domain"] = domain_url

        logger = DomainLogger(domain_dir)

        logger.log(f"TARGET: {domain_url}")

        try:
            findings = fuzz_url(
                domain_url, args.ai, domain_dir, state,
                threads=args.threads, logger=logger
            )
            all_findings.extend(findings)
            msg = f"Done: {domain_url} | Findings: {len(findings)} | AI calls: {_ai_budget['calls']}/{args.ai_budget}"
            print(f"\n[+] {msg}")
            logger.log(msg)

            state["completed"].append(domain_url)
            state["current"] = None
            save_state(state, args.output)

        except BudgetExhausted as e:
            # Reload findings.json — save_finding() wrote each hit as it was found
            partial = []
            pf = os.path.join(domain_dir, "findings.json")
            if os.path.exists(pf):
                try:
                    with open(pf) as f:
                        partial = json.load(f)
                except Exception:
                    pass
            all_findings.extend(partial)
            warn = f"BUDGET EXHAUSTED — {domain_url} processed partially ({_ai_budget['calls']} calls). {len(partial)} findings saved. Increase --ai-budget to fully process."
            print(f"\n[!] {warn}")
            logger.log(f"WARNING: {warn}")
            # Still mark completed — retrying would just exhaust budget again
            state["completed"].append(domain_url)
            state["current"] = None
            save_state(state, args.output)

        except KeyboardInterrupt:
            print("\n[!] Interrupted — state saved. Run same command to resume.")
            logger.log("INTERRUPTED by user")
            state["queue"].insert(0, domain_url)
            save_state(state, args.output)
            sys.exit(0)
        except Exception as e:
            print(f"[!] Error on {domain_url}: {e} — moved to end of queue for retry")
            logger.log(f"ERROR: {e} — requeued")
            state["queue"].append(domain_url)
            state["current"] = None
            save_state(state, args.output)
        finally:
            logger.close()

    # Summary
    critical = [f for f in all_findings if f.get("severity") == "critical"]
    high     = [f for f in all_findings if f.get("severity") == "high"]
    medium   = [f for f in all_findings if f.get("severity") == "medium"]

    print(f"\n{'='*60}")
    print(f"[*] ALL DONE | Total findings: {len(all_findings)}")
    print(f"    Critical : {len(critical)}")
    print(f"    High     : {len(high)}")
    print(f"    Medium   : {len(medium)}")

    summary = {
        "timestamp":      datetime.now().isoformat(),
        "total_findings": len(all_findings),
        "critical":       len(critical),
        "high":           len(high),
        "medium":         len(medium),
        "findings":       all_findings
    }
    summary_file = os.path.join(args.output, "summary.json")
    with open(summary_file, 'w') as f:
        json.dump(summary, f, indent=2)
    print(f"[*] Summary: {summary_file}")


if __name__ == "__main__":
    main()
