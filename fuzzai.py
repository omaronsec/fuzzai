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

# ─────────────────────────────────────────
#  AI BRAIN
# ─────────────────────────────────────────
def ask_ai(prompt, ai="claude", retries=3):
    """Call claude or codex CLI subprocess."""
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
    # Direct parse
    try:
        return json.loads(text)
    except Exception:
        pass
    # Markdown code block
    match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except Exception:
            pass
    # Raw scan for first { ... }
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


def is_blocked(lines, errors, stderr=""):
    """Detect WAF/rate-limit blocking from ffuf output."""
    if errors > 10:
        return True
    # Check stderr for block indicators
    if stderr:
        block_patterns = ["cloudflare", "captcha", "access denied", "waf", "blocked",
                          "rate limit", "too many requests", "forbidden by policy"]
        sl = stderr.lower()
        if any(p in sl for p in block_patterns):
            return True
    if not lines:
        return False
    # All responses same size 0 or all 429/503
    statuses = []
    for line in lines[:20]:
        m = re.search(r'Status:\s*(\d+)', line)
        if m:
            statuses.append(int(m.group(1)))
    if statuses and all(s in [429, 503, 0] for s in statuses):
        return True
    return False


# ─────────────────────────────────────────
#  STATE MANAGEMENT
# ─────────────────────────────────────────
def load_state(results_dir):
    state_file = os.path.join(results_dir, "state.json")
    if os.path.exists(state_file):
        with open(state_file) as f:
            return json.load(f)
    return {
        "completed": [],
        "queue": [],
        "current": None
    }


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
    existing_urls = {f.get("url") for f in existing}
    if finding.get("url") in existing_urls:
        return  # already saved
    existing.append(finding)
    with open(findings_file, 'w') as f:
        json.dump(existing, f, indent=2)


# ─────────────────────────────────────────
#  FFUF RUNNER
# ─────────────────────────────────────────
def count_wordlist_lines(wordlist):
    try:
        result = subprocess.run(["wc", "-l", wordlist], capture_output=True, text=True)
        return int(result.stdout.strip().split()[0])
    except Exception:
        return 10000


def run_ffuf(url, wordlist, extra_flags=None, threads=None, timeout_per_run=600):
    """Run ffuf and return (lines, error_count, stderr)."""
    t = str(threads or FFUF_THREADS)
    cmd = [
        FFUF_BIN,
        "-u", url,
        "-w", wordlist,
        "-t", t,
        "-timeout", str(FFUF_TIMEOUT),
        "-s",
        "-mc", "200,201,204,301,302,307,401,403,405,500"
    ]
    if extra_flags:
        cmd += extra_flags

    lines = []
    error_count = 0
    stderr_out = ""

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout_data, stderr_out = proc.communicate(timeout=timeout_per_run)
        for line in stdout_data.splitlines():
            line = line.strip()
            if not line:
                continue
            lines.append(line)
            if re.search(r'status:\s*0|connection refused|no route to host', line, re.I):
                error_count += 1
        # Also count errors from stderr
        for sline in stderr_out.splitlines():
            if re.search(r'error|failed|refused|timeout', sline, re.I):
                error_count += 1
    except subprocess.TimeoutExpired:
        proc.kill()

    return lines, error_count, stderr_out


def run_ffuf_sampled(url, wordlist, sample_ratio=0.20, extra_flags=None, threads=None):
    """Run ffuf on first N% of wordlist."""
    total = count_wordlist_lines(wordlist)
    sample_size = max(50, int(total * sample_ratio))

    tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
    count = 0
    with open(wordlist) as f:
        for line in f:
            if count >= sample_size:
                break
            tmp.write(line)
            count += 1
    tmp.close()

    try:
        lines, errors, stderr = run_ffuf(url, tmp.name, extra_flags=extra_flags, threads=threads)
    finally:
        if os.path.exists(tmp.name):
            os.unlink(tmp.name)
    return lines, errors, total, stderr


def parse_ffuf_line(line):
    """Parse one line of ffuf -s output."""
    m = re.search(
        r'^(.+?)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+),\s*Words:\s*(\d+),\s*Lines:\s*(\d+)',
        line
    )
    if m:
        return {
            "path":   m.group(1).strip(),
            "status": int(m.group(2)),
            "size":   int(m.group(3)),
            "words":  int(m.group(4)),
            "lines":  int(m.group(5))
        }
    return None


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
    results_text = "\n".join(results[:200])   # cap to avoid huge prompt
    prompt = load_prompt("filter_analysis.prompt", url=url, results=results_text)
    out = ask_ai(prompt, ai=ai)
    data = extract_json(out)
    try:
        validate_ai_json(data, ["filter_command"])
    except ValueError:
        data["filter_command"] = ""
    filter_cmd = data.get("filter_command", "")
    # Only allow safe ffuf filter flags — no shell injection
    allowed_flags = {"-fs", "-fw", "-fl", "-fc", "-fr", "-mc"}
    raw_flags = filter_cmd.split() if filter_cmd else []
    flags = []
    i = 0
    while i < len(raw_flags):
        if raw_flags[i] in allowed_flags and i + 1 < len(raw_flags):
            val = raw_flags[i + 1]
            if re.match(r'^[\d,]+$', val):   # only digits and commas
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
        # fallback to burp list
        return f"{WORDLISTS_DIR}/parameters/burp-parameter-names.txt", data, False

    tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
    for p in params:
        tmp.write(p.strip() + "\n")
    tmp.close()
    return tmp.name, data, True   # True = caller must delete this file


def judge_finding(finding, status, size, response_snippet, tech, domain, ai):
    prompt = load_prompt("findings_judge.prompt",
                         finding=finding, status=status, size=size,
                         response_snippet=response_snippet[:500],
                         tech=json.dumps(tech), domain=domain)
    out = ask_ai(prompt, ai=ai)
    data = extract_json(out)
    validate_ai_json(data, ["worth_reporting", "severity"])
    return data


# ─────────────────────────────────────────
#  DOMAIN FUZZER
# ─────────────────────────────────────────
def fuzz_url(target_url, ai, domain_dir, state, depth=0, tech=None, filter_flags=None, threads=None, _visited=None):
    """
    Recursive fuzzer for a single URL level.
    Returns list of findings.
    _visited: in-memory set for recursion dedup — never persisted to state.
    """
    if depth > MAX_DEPTH:
        return []

    if _visited is None:
        _visited = set()

    findings = []
    parsed   = urlparse(target_url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    fuzz_target = target_url.rstrip('/') + "/FUZZ"

    # Skip already visited within this domain run (prevents recursion loops)
    if fuzz_target in _visited:
        print(f"{'  '*depth}[~] Already visited: {fuzz_target} — skip")
        return []
    _visited.add(fuzz_target)

    indent = "  " * depth
    print(f"\n{indent}[+] Fuzzing depth {depth}: {target_url}")

    # ── Tech detect (only at depth 0)
    if tech is None:
        try:
            tech = tech_detect(target_url, ai)
            print(f"{indent}[*] Tech: {tech.get('technologies')} → {tech.get('primary_wordlist')}")
        except Exception as e:
            print(f"{indent}[!] Tech detect failed ({e}) — using default wordlist")
            tech = {"primary_wordlist": f"{WORDLISTS_DIR}/general/onelistforallmicro.txt"}

    wordlist = tech.get("primary_wordlist", f"{WORDLISTS_DIR}/general/onelistforallmicro.txt")
    if not os.path.exists(wordlist):
        print(f"{indent}[!] Wordlist not found: {wordlist} — using default")
        wordlist = f"{WORDLISTS_DIR}/general/onelistforallmicro.txt"

    # ── 20% sample
    print(f"{indent}[*] 20% sample run ...")
    sample_lines, errors, total, stderr = run_ffuf_sampled(
        fuzz_target, wordlist, SAMPLE_RATIO, threads=threads
    )

    # WAF check
    if is_blocked(sample_lines, errors, stderr):
        print(f"{indent}[!] Possible block detected. Retrying slow (-t 5 -p 1-3) ...")
        sample_lines, errors, total, stderr = run_ffuf_sampled(
            fuzz_target, wordlist, SAMPLE_RATIO,
            extra_flags=["-p", "1-3"], threads=5
        )
        if is_blocked(sample_lines, errors, stderr):
            print(f"{indent}[!] Still blocked — skipping {target_url}")
            return []

    print(f"{indent}[*] Sample: {len(sample_lines)} hits from ~{int(total*SAMPLE_RATIO)} reqs")

    # ── Filter analysis
    if filter_flags is None:
        filter_flags = []
        if sample_lines:
            try:
                filter_flags, fdata = analyze_and_filter(target_url, sample_lines, ai)
                print(f"{indent}[*] Filters: {fdata.get('filter_command', 'none')}")
                if fdata.get("real_findings"):
                    print(f"{indent}[*] Spotted in sample: {fdata['real_findings']}")
            except Exception as e:
                print(f"{indent}[!] Filter analysis failed ({e}) — continuing without filter")

    # ── Full run with filters
    print(f"{indent}[*] Full run with filters ...")
    full_lines, _, _ = run_ffuf(fuzz_target, wordlist, extra_flags=filter_flags, threads=threads)

    # ── Sensitive wordlist pass
    sensitive_wl = f"{WORDLISTS_DIR}/sensitive/sensitive-combined.txt"
    if os.path.exists(sensitive_wl):
        print(f"{indent}[*] Sensitive wordlist pass ...")
        sens_lines, _, _ = run_ffuf(fuzz_target, sensitive_wl, extra_flags=filter_flags, threads=threads)
        full_lines += sens_lines

    # Deduplicate results
    seen_paths = set()
    unique_lines = []
    for line in full_lines:
        r = parse_ffuf_line(line)
        if r and r["path"] not in seen_paths:
            seen_paths.add(r["path"])
            unique_lines.append(line)

    # Save raw
    raw_file = os.path.join(domain_dir, f"raw_depth{depth}.txt")
    with open(raw_file, 'w') as f:
        f.write("\n".join(unique_lines))
    print(f"{indent}[*] {len(unique_lines)} unique results saved → {raw_file}")

    # ── Classify and act
    for line in unique_lines:
        r = parse_ffuf_line(line)
        if not r:
            continue

        path   = r["path"]
        status = r["status"]
        size   = r["size"]
        words  = r["words"]
        full_url = base_url + "/" + path.lstrip("/")

        try:
            # Get real headers + redirect for this specific result
            resp_headers, redirect = fetch_headers(full_url)

            classification = classify_path(
                base_url, path, status, size, words, resp_headers, redirect, ai
            )
            action   = classification.get("action", "skip")
            priority = classification.get("priority", "low")
            print(f"{indent}  → {path} [{status}] = {action} ({priority})")

            # ── interesting_file
            if action == "interesting_file":
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
                except Exception as e:
                    print(f"{indent}  [!] Judge failed ({e}) — skipping")
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
                    print(f"{indent}  [!!!] FINDING [{sev.upper()}]: {finding['title']}")

            # ── go_deeper
            elif action == "go_deeper" and depth < MAX_DEPTH:
                sub_url = base_url + "/" + path.lstrip("/").rstrip("/")
                sub_findings = fuzz_url(
                    sub_url, ai, domain_dir, state,
                    depth=depth + 1, tech=tech, filter_flags=filter_flags, threads=threads,
                    _visited=_visited
                )
                findings.extend(sub_findings)

            # ── param_fuzz
            elif action == "param_fuzz":
                param_file, param_data, is_temp = generate_param_wordlist(
                    base_url, path, tech, status, resp_headers, ai
                )
                total_params = param_data.get("total_params", "?")
                print(f"{indent}  [*] Param fuzzing {path} ({total_params} params) ...")

                try:
                    # Pass 1: fuzz param name with test value — find what params exist
                    param_fuzz_url = full_url + "?FUZZ=testvalue"
                    p1_lines, _, _ = run_ffuf(
                        param_fuzz_url, param_file,
                        extra_flags=filter_flags,
                        threads=threads
                    )

                    # Pass 2: fuzz param name with traversal value — find file-read params
                    traverse_fuzz_url = full_url + "?FUZZ=../../etc/passwd"
                    p2_lines, _, _ = run_ffuf(
                        traverse_fuzz_url, param_file,
                        extra_flags=["-mr", "root:x:"],
                        threads=threads
                    )

                    # Tag each line with the test value that found it
                    tagged = ([(l, "testvalue") for l in p1_lines] +
                              [(l, "../../etc/passwd") for l in p2_lines])

                    # Parse baseline sizes from filter flags — handle comma-separated values
                    baseline_sizes = set()
                    for m in re.finditer(r'-fs\s+([\d,]+)', " ".join(filter_flags)):
                        for val in m.group(1).split(','):
                            try:
                                baseline_sizes.add(int(val.strip()))
                            except ValueError:
                                pass

                    seen_params = set()
                    for pline, test_val in tagged:
                        pd = parse_ffuf_line(pline)
                        if not pd:
                            continue
                        param_name = pd["path"]
                        if param_name in seen_params:
                            continue
                        seen_params.add(param_name)
                        param_path = f"{path}?{param_name}={test_val}"

                        # Only save if response is meaningfully different (not same size as baseline)
                        if baseline_sizes and pd["size"] in baseline_sizes:
                            continue

                        # Let AI judge if this param finding is worth reporting
                        try:
                            psnippet = ""
                            try:
                                pr = requests.get(f"{full_url}?{param_name}={test_val}",
                                                  timeout=8, headers={"User-Agent": "Mozilla/5.0"})
                                psnippet = pr.text[:300]
                            except Exception:
                                pass

                            pjudge = judge_finding(param_path, pd["status"], pd["size"],
                                                   psnippet, tech, parsed.netloc, ai)
                            if pjudge.get("worth_reporting"):
                                pfinding = {
                                    "url":         base_url + "/" + param_path.lstrip("/"),
                                    "path":        param_path,
                                    "status":      pd["status"],
                                    "size":        pd["size"],
                                    "severity":    pjudge.get("severity", "medium"),
                                    "title":       pjudge.get("title", f"Parameter: {param_name}"),
                                    "description": pjudge.get("description", ""),
                                    "impact":      pjudge.get("impact", ""),
                                    "steps":       pjudge.get("steps", [])
                                }
                                findings.append(pfinding)
                                save_finding(pfinding, domain_dir)
                                print(f"{indent}  [!!!] PARAM FINDING [{pfinding['severity'].upper()}]: {pfinding['title']}")
                        except Exception as e:
                            print(f"{indent}  [!] Param judge failed ({e})")

                finally:
                    if is_temp and os.path.exists(param_file):
                        os.unlink(param_file)

        except Exception as e:
            print(f"{indent}  [!] Error on {path}: {e}")
            continue

    return findings


# ─────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────
def main():
    global FFUF_THREADS, MAX_DEPTH
    parser = argparse.ArgumentParser(
        description="fuzzai — AI-powered web fuzzer for file & param discovery"
    )
    parser.add_argument("-u", "--url",     help="Single target URL")
    parser.add_argument("-l", "--list",    help="File with list of URLs/domains")
    parser.add_argument("--ai",            choices=["claude", "codex"], default="claude",
                        help="AI provider (default: claude)")
    parser.add_argument("--threads",       type=int, default=FFUF_THREADS,
                        help=f"ffuf threads (default: {FFUF_THREADS})")
    parser.add_argument("--depth",         type=int, default=MAX_DEPTH,
                        help=f"Max recursion depth (default: {MAX_DEPTH})")
    parser.add_argument("--output",        default=RESULTS_DIR,
                        help=f"Output dir (default: {RESULTS_DIR})")
    args = parser.parse_args()

    if not args.url and not args.list:
        parser.print_help()
        sys.exit(1)

    # Wire CLI args into runtime globals
    FFUF_THREADS = args.threads
    MAX_DEPTH    = args.depth

    # Build domain queue
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

    # Resume or fresh start
    if not state["queue"]:
        state["queue"] = [d for d in domains if d not in state["completed"]]
    else:
        # Add any new domains not already in queue or completed
        existing = set(state["queue"]) | set(state["completed"])
        for d in domains:
            if d not in existing:
                state["queue"].append(d)

    save_state(state, args.output)

    total_in_queue = len(state["queue"])
    print(f"[*] fuzzai | AI: {args.ai} | Threads: {args.threads} | Depth: {args.depth}")
    print(f"[*] Queue: {total_in_queue} domains | Completed: {len(state['completed'])}")
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

        try:
            findings = fuzz_url(
                domain_url, args.ai, domain_dir, state,
                threads=args.threads
            )
            all_findings.extend(findings)
            print(f"\n[+] Done: {domain_url} | Findings: {len(findings)}")

            state["completed"].append(domain_url)
            state["current"] = None
            save_state(state, args.output)

        except KeyboardInterrupt:
            print("\n[!] Interrupted — state saved. Run same command to resume.")
            state["queue"].insert(0, domain_url)
            save_state(state, args.output)
            sys.exit(0)
        except Exception as e:
            print(f"[!] Error on {domain_url}: {e} — moved to end of queue for retry")
            state["queue"].append(domain_url)
            state["current"] = None
            save_state(state, args.output)

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
