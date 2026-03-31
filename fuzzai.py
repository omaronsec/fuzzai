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
import signal
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from datetime import datetime

# ─────────────────────────────────────────
#  CONFIG
# ─────────────────────────────────────────
WORDLISTS_DIR = "/root/wordlists"
RESULTS_DIR   = "/root/fuzzai/results"
PROMPTS_DIR   = "/root/fuzzai/prompts"
FFUF_BIN      = "ffuf"
FFUF_THREADS  = 40
FFUF_TIMEOUT  = 10
SAMPLE_RATIO  = 0.20   # 20% before first filter analysis
MAX_DEPTH     = 3      # max recursive fuzz depth

# ─────────────────────────────────────────
#  AI BRAIN
# ─────────────────────────────────────────
def ask_ai(prompt, ai="claude", retries=3):
    """Call claude or codex CLI and return output string."""
    for attempt in range(retries):
        try:
            if ai == "claude":
                cmd = ["claude", "-p", prompt]
            else:
                cmd = ["codex", prompt]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

            # Rate limit handling
            combined = (result.stdout + result.stderr).lower()
            if any(x in combined for x in ["rate limit", "too many requests", "quota", "retry after"]):
                wait = parse_rate_limit_wait(result.stderr or result.stdout, ai)
                print(f"[~] Rate limited. Sleeping {wait}s ...")
                time.sleep(wait)
                continue

            if result.returncode != 0 and not result.stdout:
                raise RuntimeError(f"AI error: {result.stderr.strip()}")

            return result.stdout.strip()

        except subprocess.TimeoutExpired:
            print(f"[!] AI timeout on attempt {attempt+1}")
            time.sleep(10)

    raise RuntimeError("AI failed after all retries")


def parse_rate_limit_wait(error_msg, ai):
    """Extract wait time from rate limit error, fallback 300s."""
    try:
        prompt_file = os.path.join(PROMPTS_DIR, "rate_limit_recovery.prompt")
        prompt = open(prompt_file).read().replace("{error_message}", error_msg)
        out = ask_ai(prompt, ai=ai, retries=1)
        data = extract_json(out)
        return int(data.get("wait_seconds", 300))
    except Exception:
        return 300


def load_prompt(name, **kwargs):
    """Load prompt file and fill placeholders."""
    path = os.path.join(PROMPTS_DIR, name)
    with open(path) as f:
        content = f.read()
    for key, val in kwargs.items():
        content = content.replace("{" + key + "}", str(val))
    return content


def extract_json(text):
    """Robustly extract JSON from AI response."""
    # Try direct parse first
    try:
        return json.loads(text)
    except Exception:
        pass
    # Find first { ... }
    start = text.find('{')
    end = text.rfind('}') + 1
    if start != -1 and end > start:
        try:
            return json.loads(text[start:end])
        except Exception:
            pass
    # Try extracting json code block
    match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except Exception:
            pass
    raise ValueError(f"Could not extract JSON from: {text[:200]}")


# ─────────────────────────────────────────
#  HTTP HELPERS
# ─────────────────────────────────────────
def fetch_target(url):
    """Fetch URL, return headers + cleaned content."""
    try:
        r = requests.get(url, timeout=10, allow_redirects=True,
                         headers={"User-Agent": "Mozilla/5.0"})
        soup = BeautifulSoup(r.content, 'html.parser')
        for tag in soup(["script", "style", "img", "svg"]):
            tag.decompose()
        content = soup.get_text(separator=' ', strip=True)[:3000]
        return dict(r.headers), content
    except Exception as e:
        return {}, ""


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


# ─────────────────────────────────────────
#  FFUF RUNNER
# ─────────────────────────────────────────
def count_wordlist_lines(wordlist):
    try:
        result = subprocess.run(["wc", "-l", wordlist], capture_output=True, text=True)
        return int(result.stdout.strip().split()[0])
    except Exception:
        return 10000


def run_ffuf(url, wordlist, extra_flags=None, timeout_per_run=600):
    """Run ffuf and return output lines."""
    cmd = [
        FFUF_BIN,
        "-u", url,
        "-w", wordlist,
        "-t", str(FFUF_THREADS),
        "-timeout", str(FFUF_TIMEOUT),
        "-s",   # silent mode
        "-mc", "200,201,204,301,302,307,401,403,405,500"
    ]
    if extra_flags:
        cmd += extra_flags

    lines = []
    error_count = 0

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 text=True)
        for line in proc.stdout:
            line = line.strip()
            if line:
                lines.append(line)
                # Check for errors/blocks
                if "status: 0" in line.lower() or "connection refused" in line.lower():
                    error_count += 1
        proc.wait(timeout=timeout_per_run)
    except subprocess.TimeoutExpired:
        proc.kill()

    return lines, error_count


def run_ffuf_sampled(url, wordlist, sample_ratio=0.20, extra_flags=None):
    """Run ffuf on first N% of wordlist lines."""
    total = count_wordlist_lines(wordlist)
    sample_size = max(50, int(total * sample_ratio))

    # Write sample wordlist to temp file
    tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
    count = 0
    with open(wordlist) as f:
        for line in f:
            if count >= sample_size:
                break
            tmp.write(line)
            count += 1
    tmp.close()

    lines, errors = run_ffuf(url, tmp.name, extra_flags=extra_flags)
    os.unlink(tmp.name)
    return lines, errors, total


# ─────────────────────────────────────────
#  CORE PIPELINE
# ─────────────────────────────────────────
def tech_detect(url, ai):
    """Detect technology and get best wordlist."""
    print(f"[*] Tech detecting: {url}")
    headers, content = fetch_target(url)
    prompt = load_prompt("tech_detect.prompt",
                         url=url, headers=json.dumps(headers), content=content)
    out = ask_ai(prompt, ai=ai)
    return extract_json(out)


def analyze_and_filter(url, results, ai):
    """Analyze 20% results, return filter flags."""
    results_text = "\n".join(results)
    prompt = load_prompt("filter_analysis.prompt", url=url, results=results_text)
    out = ask_ai(prompt, ai=ai)
    data = extract_json(out)
    filter_cmd = data.get("filter_command", "")
    flags = filter_cmd.split() if filter_cmd else []
    return flags, data


def classify_path(url, path, status, size, words, headers, redirect, ai):
    """Classify a discovered path and decide next action."""
    prompt = load_prompt("path_classifier.prompt",
                         url=url, path=path, status=status,
                         size=size, words=words, headers=json.dumps(headers),
                         redirect=redirect or "")
    out = ask_ai(prompt, ai=ai)
    return extract_json(out)


def generate_param_wordlist(url, endpoint, tech, status, headers, ai):
    """Generate param wordlist for an endpoint."""
    prompt = load_prompt("param_wordlist.prompt",
                         url=url, endpoint=endpoint,
                         tech=json.dumps(tech), status=status,
                         headers=json.dumps(headers))
    out = ask_ai(prompt, ai=ai)
    data = extract_json(out)
    params = data.get("param_list", [])

    # Write to temp file
    tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
    for p in params:
        tmp.write(p + "\n")
    tmp.close()
    return tmp.name, data


def judge_finding(finding, status, size, response_snippet, tech, domain, ai):
    """Judge if a finding is worth reporting."""
    prompt = load_prompt("findings_judge.prompt",
                         finding=finding, status=status, size=size,
                         response_snippet=response_snippet[:500],
                         tech=json.dumps(tech), domain=domain)
    out = ask_ai(prompt, ai=ai)
    return extract_json(out)


def parse_ffuf_line(line):
    """Parse a single ffuf output line."""
    # Format: path  [Status: 200, Size: 1234, Words: 45, Lines: 12, Duration: 100ms]
    match = re.search(
        r'^(.+?)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+),\s*Words:\s*(\d+),\s*Lines:\s*(\d+)',
        line
    )
    if match:
        return {
            "path": match.group(1).strip(),
            "status": int(match.group(2)),
            "size": int(match.group(3)),
            "words": int(match.group(4)),
            "lines": int(match.group(5))
        }
    return None


# ─────────────────────────────────────────
#  DOMAIN FUZZER
# ─────────────────────────────────────────
def fuzz_domain(domain_url, ai, domain_results_dir, depth=0):
    """Full fuzzing pipeline for a single URL."""
    if depth > MAX_DEPTH:
        return []

    findings = []
    parsed = urlparse(domain_url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    print(f"\n{'  '*depth}[+] Fuzzing: {domain_url} (depth {depth})")

    # ── Step 1: Tech detect
    try:
        tech = tech_detect(domain_url, ai)
        print(f"{'  '*depth}[*] Tech: {tech.get('technologies')} | Wordlist: {tech.get('primary_wordlist')}")
    except Exception as e:
        print(f"{'  '*depth}[!] Tech detect failed: {e}")
        tech = {"primary_wordlist": f"{WORDLISTS_DIR}/general/onelistforallmicro.txt"}

    wordlist = tech.get("primary_wordlist", f"{WORDLISTS_DIR}/general/onelistforallmicro.txt")
    if not os.path.exists(wordlist):
        wordlist = f"{WORDLISTS_DIR}/general/onelistforallmicro.txt"

    fuzz_url = domain_url.rstrip('/') + "/FUZZ"

    # ── Step 2: Sample run (20%)
    print(f"{'  '*depth}[*] Running 20% sample ...")
    sample_results, errors, total = run_ffuf_sampled(fuzz_url, wordlist, SAMPLE_RATIO)

    if errors > len(sample_results) * 0.5 and errors > 5:
        print(f"{'  '*depth}[!] Too many errors ({errors}) - target may be blocking. Retrying slow ...")
        sample_results, errors, total = run_ffuf_sampled(
            fuzz_url, wordlist, SAMPLE_RATIO,
            extra_flags=["-t", "5", "-p", "1-3"]
        )
        if errors > 10:
            print(f"{'  '*depth}[!] Still blocked. Skipping {domain_url}")
            return findings

    print(f"{'  '*depth}[*] Sample: {len(sample_results)} results from ~{int(total*SAMPLE_RATIO)} requests")

    # ── Step 3: Filter analysis
    filter_flags = []
    if sample_results:
        try:
            filter_flags, filter_data = analyze_and_filter(domain_url, sample_results, ai)
            print(f"{'  '*depth}[*] Filter: {filter_data.get('filter_command', 'none')}")
            real = filter_data.get("real_findings", [])
            if real:
                print(f"{'  '*depth}[*] Real findings in sample: {real}")
        except Exception as e:
            print(f"{'  '*depth}[!] Filter analysis failed: {e}")

    # ── Step 4: Full run with filters
    print(f"{'  '*depth}[*] Running full wordlist with filters ...")
    full_results, _ = run_ffuf(fuzz_url, wordlist, extra_flags=filter_flags)

    # Also run sensitive wordlist
    sensitive_wl = f"{WORDLISTS_DIR}/sensitive/sensitive-combined.txt"
    if os.path.exists(sensitive_wl):
        print(f"{'  '*depth}[*] Running sensitive wordlist ...")
        sens_results, _ = run_ffuf(fuzz_url, sensitive_wl, extra_flags=filter_flags)
        full_results += sens_results

    # Save raw results
    raw_file = os.path.join(domain_results_dir, f"raw_depth{depth}.txt")
    with open(raw_file, 'w') as f:
        f.write("\n".join(full_results))

    # ── Step 5: Classify and act on results
    for line in full_results:
        parsed_result = parse_ffuf_line(line)
        if not parsed_result:
            continue

        path = parsed_result["path"]
        status = parsed_result["status"]
        size = parsed_result["size"]
        words = parsed_result["words"]

        full_path_url = base_url + "/" + path.lstrip("/")

        try:
            # Get redirect if any
            redirect = None
            if status in [301, 302, 307]:
                try:
                    r = requests.head(full_path_url, timeout=5, allow_redirects=False)
                    redirect = r.headers.get("Location", "")
                except Exception:
                    pass

            classification = classify_path(
                base_url, path, status, size, words, {}, redirect, ai
            )
            action = classification.get("action")
            priority = classification.get("priority", "low")

            print(f"{'  '*depth}  → {path} [{status}] = {action} ({priority})")

            if action == "interesting_file":
                # Try to get snippet
                snippet = ""
                try:
                    r = requests.get(full_path_url, timeout=10)
                    snippet = r.text[:500]
                except Exception:
                    pass

                judgment = judge_finding(path, status, size, snippet, tech,
                                         parsed.netloc, ai)
                if judgment.get("worth_reporting"):
                    finding = {
                        "url": full_path_url,
                        "path": path,
                        "status": status,
                        "size": size,
                        "severity": judgment.get("severity"),
                        "title": judgment.get("title"),
                        "description": judgment.get("description"),
                        "impact": judgment.get("impact"),
                        "steps": judgment.get("steps", [])
                    }
                    findings.append(finding)
                    print(f"{'  '*depth}  [!!!] FINDING: {judgment.get('title')} [{judgment.get('severity').upper()}]")

                    # Save finding immediately
                    findings_file = os.path.join(domain_results_dir, "findings.json")
                    existing = []
                    if os.path.exists(findings_file):
                        with open(findings_file) as ff:
                            existing = json.load(ff)
                    existing.append(finding)
                    with open(findings_file, 'w') as ff:
                        json.dump(existing, ff, indent=2)

            elif action == "go_deeper" and depth < MAX_DEPTH:
                sub_url = base_url + "/" + path.lstrip("/").rstrip("/")
                sub_findings = fuzz_domain(sub_url, ai, domain_results_dir, depth + 1)
                findings.extend(sub_findings)

            elif action == "param_fuzz":
                param_file, param_data = generate_param_wordlist(
                    base_url, path, tech, status, {}, ai
                )
                param_fuzz_url = full_path_url + "?FUZZ=testvalue"
                print(f"{'  '*depth}  [*] Param fuzzing: {path} with {param_data.get('total_params')} params")

                param_results, _ = run_ffuf(
                    param_fuzz_url, param_file,
                    extra_flags=filter_flags + ["-mr", "testvalue"]
                )
                os.unlink(param_file)

                # Also fuzz with path traversal value to find file params
                traverse_url = full_path_url + "?FUZZ=../../../etc/passwd"
                traverse_results, _ = run_ffuf(traverse_url, param_file if os.path.exists(param_file) else
                                                f"{WORDLISTS_DIR}/parameters/burp-parameter-names.txt",
                                                extra_flags=["-mr", "root:"])

                for pr in (param_results + traverse_results):
                    pdata = parse_ffuf_line(pr)
                    if pdata:
                        param_path = f"{path}?{pdata['path']}=value"
                        finding = {
                            "url": base_url + param_path,
                            "path": param_path,
                            "status": pdata["status"],
                            "size": pdata["size"],
                            "severity": "medium",
                            "title": f"Parameter Found: {pdata['path']}",
                            "description": f"Parameter {pdata['path']} found on {path}",
                            "impact": "Investigate for file read, IDOR, or other parameter-based vulnerabilities"
                        }
                        findings.append(finding)

        except Exception as e:
            print(f"{'  '*depth}  [!] Error processing {path}: {e}")
            continue

    return findings


# ─────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="fuzzai - AI-powered ffuf wrapper for file & param discovery"
    )
    parser.add_argument("-u", "--url", help="Single target URL")
    parser.add_argument("-l", "--list", help="File with list of URLs/domains")
    parser.add_argument("--ai", choices=["claude", "codex"], default="claude",
                        help="AI provider (default: claude)")
    parser.add_argument("--threads", type=int, default=FFUF_THREADS,
                        help="ffuf threads (default: 40)")
    parser.add_argument("--depth", type=int, default=MAX_DEPTH,
                        help="Max recursion depth (default: 3)")
    parser.add_argument("--output", default=RESULTS_DIR,
                        help="Output directory (default: /root/fuzzai/results)")
    args = parser.parse_args()

    if not args.url and not args.list:
        parser.print_help()
        sys.exit(1)

    # Build domain queue
    domains = []
    if args.url:
        domains.append(args.url)
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

    # Restore queue or set fresh
    if not state["queue"]:
        state["queue"] = [d for d in domains if d not in state["completed"]]
    save_state(state, args.output)

    print(f"[*] fuzzai starting | AI: {args.ai} | Domains: {len(state['queue'])} in queue")
    print(f"[*] Results: {args.output}")

    all_findings = []

    while state["queue"]:
        domain_url = state["queue"].pop(0)
        state["current"] = domain_url
        save_state(state, args.output)

        # Create domain results dir
        domain_name = urlparse(domain_url).netloc.replace(".", "_")
        domain_dir = os.path.join(args.output, domain_name)
        os.makedirs(domain_dir, exist_ok=True)

        print(f"\n{'='*60}")
        print(f"[*] TARGET: {domain_url}")
        print(f"{'='*60}")

        try:
            findings = fuzz_domain(domain_url, args.ai, domain_dir)
            all_findings.extend(findings)

            print(f"\n[+] Done: {domain_url} | Findings: {len(findings)}")
            state["completed"].append(domain_url)
            state["current"] = None
            save_state(state, args.output)

        except KeyboardInterrupt:
            print("\n[!] Interrupted. State saved. Resume by running same command.")
            save_state(state, args.output)
            sys.exit(0)
        except Exception as e:
            print(f"[!] Failed on {domain_url}: {e}")
            # Move to bottom of queue for retry
            state["queue"].append(domain_url)
            save_state(state, args.output)

    # Final summary
    print(f"\n{'='*60}")
    print(f"[*] DONE | Total findings: {len(all_findings)}")

    critical = [f for f in all_findings if f.get("severity") == "critical"]
    high     = [f for f in all_findings if f.get("severity") == "high"]
    medium   = [f for f in all_findings if f.get("severity") == "medium"]

    print(f"    Critical: {len(critical)}")
    print(f"    High:     {len(high)}")
    print(f"    Medium:   {len(medium)}")

    summary_file = os.path.join(args.output, "summary.json")
    with open(summary_file, 'w') as f:
        json.dump({
            "timestamp": datetime.now().isoformat(),
            "total_findings": len(all_findings),
            "critical": len(critical),
            "high": len(high),
            "medium": len(medium),
            "findings": all_findings
        }, f, indent=2)

    print(f"[*] Summary saved: {summary_file}")


if __name__ == "__main__":
    main()
