# fuzzai

An AI-powered web fuzzer wrapper around [ffuf](https://github.com/ffuf/ffuf) that thinks like a senior bug bounty hunter.

fuzzai uses Claude or Codex AI to make smart decisions during fuzzing — detecting technologies, filtering false positives, classifying paths, generating context-aware parameter wordlists, and triaging findings by severity.

## What it finds

- Exposed log files, backup archives (`.zip`, `.bak`, `.sql`, `.tar.gz`)
- Sensitive config files (`.env`, `wp-config.php`, `database.yml`, `.htpasswd`)
- File-serving parameters (`?file=`, `?download=`, `?filename=`, `?path=`)
- Exposed `.git` directories, `.DS_Store`, dotfiles
- Admin panels, debug endpoints, exposed database dumps

> **Not** a payload fuzzer. No XSS/SQLi/LFI payloads. Pure file and parameter discovery.

---

## How it works

```
Domain → Tech Detect → Pick Wordlist → ffuf (20% sample)
       → AI Filter Analysis → Remove false positives
       → ffuf Full Run with Filters
       → AI Path Classifier → go_deeper / param_fuzz / interesting_file / skip
       → Recurse into valid paths (up to depth 3)
       → AI Param Wordlist → Parameter fuzzing on functional endpoints
       → AI Findings Judge → Severity triage → Save report
```

### Smart filtering

Instead of manual `-fs` tuning, fuzzai runs the first 20% of requests, sends results to AI, and gets back the exact filter flags to use. If a response size or word count repeats more than 6 times — it's noise, filtered automatically.

The loop:
```
Run 20% → analyze → apply filters → run full → still noisy? → filter again → clean results
```

### Progressive recursion

When a valid path is found, AI decides what to do:

| Finding | Action |
|---------|--------|
| `/files/` 403 | go_deeper → `/files/FUZZ` |
| `/admin/download` 200 | param_fuzz → `?FUZZ=value` |
| `/backup_2023.zip` 200 | interesting_file → triage & save |
| `/about` 200 | skip |

Recursion is context-aware — AI uses security knowledge, not hardcoded rules.

### Parameter fuzzing

Parameter fuzzing only happens after a valid path is discovered — never on root. AI generates a context-aware list of parameter names based on the endpoint name, tech stack, and response. Then tests for file-serving parameters using a known test value as baseline.

---

## Requirements

- Python 3.8+
- [ffuf](https://github.com/ffuf/ffuf) installed and in PATH
- [Claude Code CLI](https://claude.ai/code) (`claude`) — for Claude Pro/Max plan usage
- OR [Codex CLI](https://github.com/openai/codex) (`codex`) — for OpenAI usage

```bash
pip install requests beautifulsoup4
```

---

## Installation

```bash
git clone https://github.com/omaronsec/fuzzai
cd fuzzai
pip install requests beautifulsoup4
chmod +x fuzzai.py
```

Make sure `ffuf` is installed:
```bash
which ffuf
# or
go install github.com/ffuf/ffuf/v2@latest
```

---

## Usage

### Single target
```bash
python3 fuzzai.py -u https://target.com
```

### Domain list
```bash
python3 fuzzai.py -l domains.txt
```

### Use Codex instead of Claude
```bash
python3 fuzzai.py -l domains.txt --ai codex
```

### Custom depth and output
```bash
python3 fuzzai.py -l targets.txt --depth 4 --output /path/to/results
```

### All options
```
-u, --url       Single target URL
-l, --list      File with list of URLs/domains (one per line)
--ai            AI provider: claude (default) or codex
--threads       ffuf thread count (default: 40)
--depth         Max recursion depth (default: 3)
--output        Output directory (default: ./results)
```

---

## AI Providers

| Provider | Command Used | Requirement |
|----------|-------------|-------------|
| Claude | `claude -p "..."` | Claude Code CLI + Pro/Max plan |
| Codex | `codex "..."` | Codex CLI + OpenAI account |

No API keys needed for Claude — uses your Pro/Max plan subscription via the CLI.

---

## Output Structure

```
results/
└── target_com/
    ├── raw_depth0.txt       ← all ffuf output at root level
    ├── raw_depth1.txt       ← ffuf output at depth 1
    ├── raw_depth2.txt       ← ffuf output at depth 2
    └── findings.json        ← triaged findings with severity
summary.json                 ← full run summary
state.json                   ← resume state (survives crashes)
```

### findings.json format
```json
[
  {
    "url": "https://target.com/backup_2023.zip",
    "path": "/backup_2023.zip",
    "status": 200,
    "size": 4521891,
    "severity": "critical",
    "title": "Exposed Database Backup File",
    "description": "...",
    "impact": "...",
    "steps": ["GET /backup_2023.zip"]
  }
]
```

---

## Resume After Crash / Rate Limit

fuzzai saves state after every domain. If it crashes, hits a rate limit, or you kill it — just run the same command again:

```bash
python3 fuzzai.py -l domains.txt
# Interrupted...

python3 fuzzai.py -l domains.txt
# [*] Resuming from state — 12 domains completed, 88 remaining
```

Rate limits are handled automatically — fuzzai parses the wait time from the error message and sleeps exactly that long before retrying.

---

## Wordlists

fuzzai expects wordlists organized in the following folder structure:

```
/root/wordlists/
├── general/      → raft-*, DirBuster, onelistforallmicro, common, big
├── cms/          → WordPress, Drupal, Joomla, Magento, Laravel, Symfony, Django...
├── tech/         → Apache, IIS, Nginx, JBoss, Java/Spring, SAP, Oracle, Jenkins...
├── subdomains/   → top1million, assetnote, bitquark, FUZZSUBS...
├── parameters/   → burp-parameter-names, session-id, env vars, JWT secrets...
├── extensions/   → web-extensions, file-extensions, raft-extensions...
└── sensitive/    → backups, dotfiles, configs, logs, secrets
```

AI selects the right wordlist automatically based on tech detection. You can use [SecLists](https://github.com/danielmiessler/SecLists) and [Assetnote Wordlists](https://wordlists.assetnote.io/) to populate these folders.

---

## Prompts

All AI decision logic lives in `prompts/` as plain text files. Edit them to tune behavior:

| Prompt | Purpose |
|--------|---------|
| `tech_detect.prompt` | Detect tech stack → pick wordlist |
| `filter_analysis.prompt` | Analyze 20% results → build ffuf filters |
| `path_classifier.prompt` | Classify path → decide next action |
| `param_wordlist.prompt` | Generate context-aware param names |
| `findings_judge.prompt` | Triage findings → severity rating |
| `rate_limit_recovery.prompt` | Parse wait time from rate limit errors |

---

## Disclaimer

This tool is intended for authorized security testing and bug bounty programs only. Only use against targets you have explicit permission to test. The authors are not responsible for misuse.

---

## License

MIT
