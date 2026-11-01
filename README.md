# AndroAI Case Processor

Cron-based pipeline that discovers Zintel cases created by `clean_smba_cases` (SMBA + Crawler workflows), downloads their samples, runs **androAiV2** LLM analysis, and uploads the resulting artifact ZIP + structured comment back to the same case.

## How It Works

1. Reads config to get list of researchers + their enabled case-name prefixes
2. For each researcher + prefix: queries Zintel for cases with `status=assigned`
3. Filters out already-processed cases (tracked in `data/processed_state.json`)
4. For each new case:
   - Fetches sample MD5 list from the case
   - Downloads APKs via Zintel bulk download
   - (Optional) YARA pre-scan to skip already-detected samples
   - Runs androAiV2 LLM analysis
   - Parses verdicts, builds artifact ZIP (reports + YARA + Snort rules)
   - Attaches ZIP to the Zintel case + adds structured comment
   - Marks case as processed in state file
5. Does **not** change case status (leaves as `assigned` for researcher review)

## Case Name Conventions

| Source | Prefix | Created by |
|--------|--------|------------|
| SMBA benign/malicious | `SMBA_LLM_{researcher_id}_` | `clean_smba_cases` (llm_case_creation) |
| SMBA benign/malicious | `SMBA_Suspicious_{researcher_id}_` | `clean_smba_cases` (llm_case_creation) |
| Crawler | `Crawler_NotOnVT_{researcher_id}_` | `clean_smba_cases` (crawler workflow) |
| Crawler | `Crawler_Malicious_{researcher_id}_` | `clean_smba_cases` (crawler workflow) |
| Crawler | `Crawler_LowScore_SuspPerm_{researcher_id}_` | `clean_smba_cases` (crawler workflow) |

## Setup

```bash
# Clone and install
git clone <repo-url>
cd androai_case_processor
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Configure
cp config/config.yaml.example config/config.yaml
cp .env.example .env
# Edit both files with real credentials and paths

# Test
python3 llm_pipeline.py --dry-run

# Cron (every Sunday at 2 AM)
0 2 * * 0 cd /path/to/androai_case_processor && .venv/bin/python3 llm_pipeline.py >> logs/cron.log 2>&1
```
