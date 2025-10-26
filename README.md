# Automated Multi-Agent Security (AMAS)

AMAS is a sandbox for running end-to-end security investigations with CrewAI agents that are grounded in a Model Context Protocol (MCP) server backed by curated enterprise datasets. The project simulates how a security operations centre could triage alerts, gather evidence, judge performance, and iterate on workflows.

## Highlights
- Two-stage CrewAI workflow (Control Tower and Issue Analysis agents) orchestrated via `src/workflow.py`.
- MCP server (`src/mcp.py`) that exposes 10 enterprise datasets through CrewAI tools.
- Reproducible sample alerts, ground truth, and judge results stored under `data/`.
- Batch pipeline (`src/generate_reports.py`) that runs every alert, captures transcripts, and optionally scores reports with a Vertex AI judge.
- Jupyter notebook (`notebooks/evaluate_agents.ipynb`) for ad hoc analysis of generated reports and evaluations.

## Repository Layout
- `src/`: Python package that houses all runtime components.
  - `simulate.py`: CLI entry point for running a single investigation.
  - `generate_reports.py`: Batch runner and judge integration.
  - `workflow.py`: Crew and task orchestration.
  - `agents.py`: Agent prompt assembly and MCP tool wiring.
  - `mcp.py`: FastMCP server exposing security datasets.
  - `security_data.py`: Dataset loader/query layer with filtering helpers.
  - `documentation.py`: Loads Markdown documentation into prompts.
  - `tooling.py`: Adapts MCP tools to CrewAI's tool interface.
- `data/`: Demo datasets and generated artefacts.
  - `alerts.json`: Catalogue of scenarios consumed by the simulator.
  - `ground_truth.json`: Expected outputs per scenario for evaluation.
  - `desired_output.json`: Example Automated Analysis Report instance.
  - `documentation/`: Markdown prompt assets surfaced to the agents (`SYSTEM_PROMPT.md`, `ORGANISATION_ASSETS.md`, `DESIRED_OUTPUT.md`).
  - `organisation-documents/`: JSON sources that back each MCP tool (CMDB, IAM, VLANs, policies, threat intel, UEBA, EDR events, DNS/proxy logs, vulnerability scans, and response playbooks).
  - `evaluations/vertex_judge_results.json`: Historic LLM-as-judge results for reference.
  - `output/combined_reports.json`: Aggregated results from the latest batch run.
  - `output/scenarios/`: Per-scenario transcripts (ignored by git; regenerated locally).
- `notebooks/evaluate_agents.ipynb`: Notebook for exploring agent outputs and judge scores.
- `requirements.txt`: Runtime dependencies for CrewAI, MCP, and LLM connectors.
- `secrets/`: Local-only credential storage (ignored from version control).

## Installation
1. Install Python 3.10 or later.
2. Create and activate a virtual environment:
   ```bash
   python -m venv .venv
   # macOS / Linux
   source .venv/bin/activate
   # Windows PowerShell
   .\.venv\Scripts\Activate.ps1
   ```
3. Install dependencies:
   ```bash
   python -m pip install --upgrade pip
   python -m pip install -r requirements.txt
   ```

## Configuration
- Copy or create an `.env` file (not committed) with the relevant settings, then load it into your shell.
- Core variables:
  - `AMAS_LLM_PROVIDER`: `vertex` (default), `google-genai`, or `openai`.
  - `GOOGLE_APPLICATION_CREDENTIALS`: Path to your Vertex AI service account JSON (defaults to `secrets/gcp/service-account.json` if present).
  - `AMAS_VERTEX_PROJECT`, `AMAS_VERTEX_LOCATION`, `AMAS_VERTEX_MODEL`: Vertex AI project and model identifiers.
  - `AMAS_OPENAI_MODEL`, `OPENAI_API_KEY` or `AMAS_GOOGLE_MODEL`, `GOOGLE_API_KEY`: Required when using OpenAI or Gemini APIs.
  - `AMAS_DATA_DIR`: Optional override if you relocate the demo datasets outside the repo.
  - `AMAS_LLM_TEMPERATURE`: Float controlling response creativity (defaults to `0.8`).
- Store credentials under `secrets/` (ignored by git). For Vertex AI, place the JSON file at `secrets/gcp/service-account.json` or point `GOOGLE_APPLICATION_CREDENTIALS` to another location.

## Security Data Catalogue
The MCP server exposes one tool per dataset. Each tool accepts free-text `query` and optional structured `filters` (dot notation supported). The datasets are defined in `src/security_data.py`:
- `query_cmdb_assets`: Configuration Management Database entries.
- `query_iam_users`: IAM and HR user profiles.
- `query_network_vlans`: VLAN and network segmentation docs.
- `query_service_usage_policy`: Approved port and service policies.
- `query_threat_intelligence`: Threat indicator feed.
- `query_ueba_profiles`: Baseline UEBA behaviour profiles.
- `query_edr_events`: Endpoint detection telemetry (process, file, network events).
- `query_dns_and_proxy_logs`: DNS and proxy logs, tagged with `log_type`.
- `query_vulnerability_findings`: Vulnerability scan findings.
- `query_incident_response_playbooks`: Response playbooks linked to MITRE ATT&CK.

`SecurityDataRepository` automatically finds these JSON files under `data/organisation-documents/` (or the path provided via `AMAS_DATA_DIR`), normalises DNS/proxy payloads, and handles filtering logic.

## Running Single Investigations
List available scenarios:
```bash
python -m src.simulate --list
```

Run a specific alert end-to-end (spins up the MCP server, assembles agents, and prints the final Automated Analysis Report):
```bash
python -m src.simulate --scenario "Suspicious - External Port Scan" --llm-provider vertex
```

Flags of interest:
- `--alerts-file`: Point to a custom catalogue.
- `--scenario` / `--index`: Choose the alert to investigate.
- `--llm-provider`: Override the active LLM backend at runtime.

## Batch Report Generation and Evaluation
Generate reports for every scenario and persist artefacts:
```bash
python -m src.generate_reports \
  --llm-provider vertex \
  --scenario-dir data/output/scenarios \
  --combined-report data/output/combined_reports.json
```

Optional automatic judging (requires Vertex AI Generative Model access and populated environment variables):
```bash
python -m src.generate_reports \
  --llm-provider vertex \
  --judge-model gemini-2.5-flash \
  --judge-output data/output/judge_results.json
```
This writes:
- `data/output/scenarios/<slug>.json`: One JSON per scenario containing the raw alert, agent output, and verbose CrewAI logs (git-ignored).
- `data/output/combined_reports.json`: Summary object with status per scenario.
- `data/output/judge_results.json`: LLM-as-judge evaluation results when `--judge-model` is supplied.

## Reproducing the Demo Run
1. Install dependencies and configure environment variables as described above.
2. Ensure `data/organisation-documents/` and `data/documentation/` remain in place (or set `AMAS_DATA_DIR`).
3. Execute `python -m src.generate_reports --llm-provider <provider>` to regenerate combined outputs.
4. Review the consolidated output in `data/output/combined_reports.json`, then inspect per-scenario transcripts under `data/output/scenarios/`.
5. (Optional) Produce judge scores with `--judge-model` and compare against the historical baseline in `data/evaluations/vertex_judge_results.json`.

## Notebook Workflow
- Open `notebooks/evaluate_agents.ipynb` in JupyterLab or VS Code to explore generated reports, compare against ground truth, or visualise judge scores.
- The notebook expects the JSON artefacts produced by `src.generate_reports.py` and can be adapted for custom analytics.

## Extending the System
- Add new datasets by updating `DATASET_CATALOGUE` in `src/security_data.py` and supplying the corresponding JSON file.
- Introduce additional CrewAI tasks or agents by modifying `src/workflow.py` and `src/agents.py` (the `AgentBundle` already includes an `overall_analysis` agent for future expansion).
- Override prompts or schemas by editing the Markdown files in `data/documentation/`.
- Point to alternate alert catalogues or output directories using the CLI flags provided by `simulate.py` and `generate_reports.py`.

## .gitignore and Local-Only Artefacts
The following paths are intentionally excluded from version control:
- `secrets/`: Credential files such as service account keys.
- `.env`: Environment-specific configuration.
- `.venv`, `.idea`: Local virtual environments and IDE metadata.
- `data/output/scenarios/`: Generated investigation transcripts and logs (regenerate via the batch runner).

## Troubleshooting
- `FileNotFoundError` referencing documentation or datasets: verify that the `data/` directory is present or set `AMAS_DATA_DIR` to your data root.
- Import errors for `langchain_google_vertexai`, `langchain_google_genai`, or `langchain_openai`: install the corresponding extra from `requirements.txt` and ensure it is available in the active virtual environment.
- Vertex AI authentication failures: confirm `GOOGLE_APPLICATION_CREDENTIALS` and `AMAS_VERTEX_PROJECT` are set and that the service account has Vertex AI permissions.
- Empty judge outputs: ensure the specified model name is available in your project and that `google-cloud-aiplatform` is installed (included in `requirements.txt`).
