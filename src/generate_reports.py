"""Utilities for generating MAS investigation reports across all scenarios."""

from __future__ import annotations

import argparse
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from string import Template
from dataclasses import asdict, is_dataclass
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional

from .security_data import SecurityDataRepository
from .simulate import create_llm, load_alerts
from .workflow import InvestigationError, run_alert_investigation


def slugify(text: str) -> str:
    """Return a filesystem-safe slug for the supplied text."""

    slug = text.lower().strip()
    slug = re.sub(r"[^a-z0-9]+", "_", slug)
    return slug.strip("_")


def ensure_directory(path: Path) -> None:
    """Create ``path`` if it does not already exist."""

    path.mkdir(parents=True, exist_ok=True)


def _json_default(value: Any) -> Any:
    """Best-effort conversion for JSON serialization."""

    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value):
        return asdict(value)
    model_dump = getattr(value, "model_dump", None)
    if callable(model_dump):
        return model_dump()
    dict_method = getattr(value, "dict", None)
    if callable(dict_method):
        return dict_method()
    if isinstance(value, set):
        return list(value)
    return str(value)


def write_json(path: Path, payload: Any) -> None:
    """Serialize payload to JSON with UTF-8 encoding."""

    ensure_directory(path.parent)
    path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False, default=_json_default),
        encoding="utf-8",
    )


def load_ground_truth(path: Path) -> Dict[str, Any]:
    """Load ground truth expectations keyed by scenario."""

    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    return {item["scenario"]: item for item in data}


def load_judge_template(system_prompt_path: Path) -> Template:
    """Extract the judge template from SYSTEM_PROMPT.md."""

    text = system_prompt_path.read_text(encoding="utf-8")
    marker = "### 4. Evaluation Judge Prompt Template"
    if marker not in text:
        raise ValueError(f"Unable to locate '{marker}' in {system_prompt_path}")
    section = text.split(marker, 1)[1]
    parts = section.split("```")
    if len(parts) < 3:
        raise ValueError("Judge prompt fenced block not found in SYSTEM_PROMPT.md")
    return Template(parts[1].strip())


def initialise_judge_model(model_name: str, location: Optional[str] = None):
    """Initialise a Vertex AI generative model for judging."""

    try:
        import vertexai
        from vertexai.generative_models import GenerativeModel
    except ImportError as exc:  # pragma: no cover - requires extra dependency
        raise ImportError(
            "google-cloud-aiplatform is required for judge evaluation. "
            "Install it via `pip install google-cloud-aiplatform`."
        ) from exc

    project = os.environ.get("AMAS_VERTEX_PROJECT")
    if not project:
        raise EnvironmentError("Environment variable AMAS_VERTEX_PROJECT must be set.")

    location = location or os.environ.get("AMAS_VERTEX_LOCATION", "europe-west4")
    vertexai.init(project=project, location=location)
    return GenerativeModel(model_name)


def judge_reports(
    combined_reports: Iterable[Dict[str, Any]],
    ground_truth: Dict[str, Any],
    template: Template,
    model,
    *,
    temperature: float = 0.1,
) -> List[Dict[str, Any]]:
    """Evaluate each MAS report using the supplied judge model."""

    results: List[Dict[str, Any]] = []
    for entry in combined_reports:
        scenario = entry["scenario"]
        if scenario not in ground_truth:
            raise KeyError(f"Ground truth not found for scenario '{scenario}'")

        prompt = template.substitute(
            ground_truth=json.dumps(ground_truth[scenario], indent=2, ensure_ascii=False),
            agent_report=json.dumps(entry["report"], indent=2, ensure_ascii=False),
        )
        response = model.generate_content(
            prompt,
            generation_config={"temperature": temperature},
        )
        text_response = getattr(response, "text", "").strip()
        if not text_response and getattr(response, "candidates", None):
            text_response = response.candidates[0].content.parts[0].text
        try:
            evaluation = json.loads(text_response)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Judge response was not valid JSON: {text_response}") from exc
        results.append(
            {
                "scenario": scenario,
                "evaluation": evaluation,
            }
        )
    return results


def generate_reports(
    alerts_file: Path,
    *,
    provider: str,
    scenario_dir: Path,
    combined_path: Path,
    judge_output_path: Optional[Path] = None,
    judge_model_name: Optional[str] = None,
    judge_temperature: float = 0.1,
    system_prompt_path: Optional[Path] = None,
    ground_truth_path: Optional[Path] = None,
) -> None:
    """Run investigations for each alert and persist outputs."""

    alerts = load_alerts(alerts_file)
    llm = create_llm(provider)
    repository = SecurityDataRepository()

    combined_entries: List[Dict[str, Any]] = []

    ensure_directory(scenario_dir)
    for alert in alerts:
        scenario = alert.get("scenario", "Unknown Scenario")
        slug = slugify(scenario)
        scenario_path = scenario_dir / f"{slug}.json"
        try:
            result, logs = run_alert_investigation(
                alert_payload=alert,
                llm=llm,
                repository=repository,
                capture_logs=True,
            )
        except InvestigationError as exc:
            error_message = str(exc)
            failure_payload = {
                "scenario": scenario,
                "alert": alert,
                "error": error_message,
            }
            if exc.logs:
                failure_payload["logs"] = exc.logs
            write_json(scenario_path, failure_payload)
            combined_entries.append(
                {
                    "scenario": scenario,
                    "status": "failed",
                    "error": error_message,
                    "report_path": str(scenario_path.relative_to(scenario_dir)),
                }
            )
            print(f"[WARN] Investigation failed for '{scenario}': {error_message}", flush=True)
            continue

        scenario_payload = {
            "scenario": scenario,
            "alert": alert,
            "report": result,
            "logs": logs,
        }
        write_json(scenario_path, scenario_payload)

        combined_entries.append(
            {
                "scenario": scenario,
                "status": "completed",
                "report": result,
                "report_path": str(scenario_path.relative_to(scenario_dir)),
            }
        )

    combined_payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "llm_provider": provider,
        "scenarios": combined_entries,
    }
    write_json(combined_path, combined_payload)

    if judge_output_path and judge_model_name:
        if system_prompt_path is None or ground_truth_path is None:
            raise ValueError(
                "system_prompt_path and ground_truth_path are required for judge evaluation."
            )
        template = load_judge_template(system_prompt_path)
        ground_truth = load_ground_truth(ground_truth_path)
        judge_model = initialise_judge_model(judge_model_name)
        evaluations = judge_reports(
            combined_entries,
            ground_truth=ground_truth,
            template=template,
            model=judge_model,
            temperature=judge_temperature,
        )
        judge_payload = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "llm_provider": provider,
            "judge_model": judge_model_name,
            "results": evaluations,
        }
        write_json(judge_output_path, judge_payload)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate MAS investigation reports for all alert scenarios."
    )
    parser.add_argument(
        "--alerts-file",
        type=Path,
        default=Path("data/alerts.json"),
        help="Path to the alerts JSON catalogue (default: data/alerts.json).",
    )
    parser.add_argument(
        "--llm-provider",
        type=str,
        default=os.environ.get("AMAS_LLM_PROVIDER", "vertex"),
        help="LLM provider to use (default: value from AMAS_LLM_PROVIDER or 'vertex').",
    )
    parser.add_argument(
        "--scenario-dir",
        type=Path,
        default=Path("data/output/scenarios"),
        help="Directory to store per-scenario reports (default: data/output/scenarios).",
    )
    parser.add_argument(
        "--combined-report",
        type=Path,
        default=Path("data/output/combined_reports.json"),
        help="Destination for the combined report JSON (default: data/output/combined_reports.json).",
    )
    parser.add_argument(
        "--judge-output",
        type=Path,
        default=Path("data/output/judge_results.json"),
        help="Destination for judge evaluation JSON (default: data/output/judge_results.json).",
    )
    parser.add_argument(
        "--judge-model",
        type=str,
        default=None,
        help="Vertex AI model name for LLM-as-judge evaluation. If omitted, evaluation is skipped.",
    )
    parser.add_argument(
        "--judge-temperature",
        type=float,
        default=0.1,
        help="Sampling temperature for the judge model (default: 0.1).",
    )
    parser.add_argument(
        "--system-prompt-path",
        type=Path,
        default=Path("data/documentation/SYSTEM_PROMPT.md"),
        help="Path to SYSTEM_PROMPT.md containing the judge template.",
    )
    parser.add_argument(
        "--ground-truth-path",
        type=Path,
        default=Path("data/ground_truth.json"),
        help="Path to the ground truth JSON (default: data/ground_truth.json).",
    )
    return parser


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()

    judge_output_path: Optional[Path] = args.judge_output if args.judge_model else None

    generate_reports(
        alerts_file=args.alerts_file,
        provider=args.llm_provider,
        scenario_dir=args.scenario_dir,
        combined_path=args.combined_report,
        judge_output_path=judge_output_path,
        judge_model_name=args.judge_model,
        judge_temperature=args.judge_temperature,
        system_prompt_path=args.system_prompt_path,
        ground_truth_path=args.ground_truth_path,
    )


if __name__ == "__main__":
    main()
