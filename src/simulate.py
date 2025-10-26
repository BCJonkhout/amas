"""Command-line entry point for running AMAS investigations end-to-end."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any, Dict, List

from crewai.llm import LLM

try:
    from .workflow import run_alert_investigation
    from .security_data import SecurityDataRepository
except ImportError:  # pragma: no cover - allows running as a script
    from workflow import run_alert_investigation  # type: ignore[no-redef]
    from security_data import SecurityDataRepository  # type: ignore[no-redef]


def _ensure_google_credentials() -> None:
    if os.environ.get("GOOGLE_APPLICATION_CREDENTIALS"):
        return

    base_dir = Path(__file__).resolve().parents[1] / "secrets"
    for candidate in (
        base_dir / "gcp" / "service-account.json",
        base_dir / "gcp.json",
    ):
        if candidate.is_file():
            os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = str(candidate)
            return


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the AMAS security investigation workflow.")
    parser.add_argument(
        "--alerts-file",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "data" / "alerts.json",
        help="Path to the alerts JSON catalogue.",
    )
    parser.add_argument(
        "--scenario",
        type=str,
        default=None,
        help="Select an alert by scenario name.",
    )
    parser.add_argument(
        "--index",
        type=int,
        default=0,
        help="Select an alert by index if --scenario is not provided.",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List available alert scenarios and exit.",
    )
    parser.add_argument(
        "--llm-provider",
        type=str,
        default=os.environ.get("AMAS_LLM_PROVIDER", "vertex"),
        help="LLM provider to use (vertex|google-genai|openai). Can also be set via AMAS_LLM_PROVIDER env var.",
    )
    return parser.parse_args()


def load_alerts(alerts_file: Path) -> List[Dict[str, Any]]:
    if not alerts_file.is_file():
        raise FileNotFoundError(f"Alerts file not found: {alerts_file}")

    with alerts_file.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)

    alerts = payload.get("cyber_security_alerts")
    if not isinstance(alerts, list):
        raise ValueError("Unexpected alerts JSON format. Expected 'cyber_security_alerts' list.")
    return alerts


def choose_alert(alerts: List[Dict[str, Any]], scenario: str | None, index: int) -> Dict[str, Any]:
    if scenario:
        for alert in alerts:
            if alert.get("scenario", "").lower() == scenario.lower():
                return alert
        raise ValueError(f"Scenario '{scenario}' not found in alerts catalogue.")
    if index < 0 or index >= len(alerts):
        raise IndexError(f"Alert index {index} out of range. Available range: 0-{len(alerts) - 1}.")
    return alerts[index]


def create_llm(provider: str):
    provider = provider.lower()
    temperature = float(os.environ.get("AMAS_LLM_TEMPERATURE", "0.8"))

    if provider in {"vertex", "google", "google-vertex"}:
        _ensure_google_credentials()
        model_name = os.environ.get("AMAS_VERTEX_MODEL", "gemini-2.5-flash")
        project = os.environ.get("AMAS_VERTEX_PROJECT") or os.environ.get("GOOGLE_CLOUD_PROJECT")
        location = os.environ.get("AMAS_VERTEX_LOCATION", "europe-west4")

        if not model_name.startswith("gemini/"):
            model_name = f"gemini/{model_name}"

        llm_kwargs: Dict[str, Any] = {"temperature": temperature, "location": location}
        if project:
            llm_kwargs["project"] = project
        return LLM(model=model_name, **llm_kwargs)

    if provider in {"google-genai", "gemini"}:
        model_name = os.environ.get("AMAS_GOOGLE_MODEL", "gemini-2.5-flash")
        if not model_name.startswith("gemini/"):
            model_name = f"gemini/{model_name}"
        return LLM(model=model_name, temperature=temperature)

    if provider == "openai":
        model_name = os.environ.get("AMAS_OPENAI_MODEL", "gpt-4o-mini")
        return LLM(model=model_name, temperature=temperature)

    raise ValueError(f"Unsupported LLM provider '{provider}'. Expected 'vertex', 'google-genai', or 'openai'.")


def main() -> None:
    args = parse_args()
    alerts = load_alerts(args.alerts_file)

    if args.list:
        for idx, alert in enumerate(alerts):
            scenario = alert.get("scenario", f"Alert #{idx}")
            probe_id = alert.get("alert", {}).get("General", {}).get("Probe_ID")
            print(f"{idx:02d}: {scenario} (Probe_ID={probe_id})")
        return

    alert = choose_alert(alerts, scenario=args.scenario, index=args.index)
    llm = create_llm(args.llm_provider)
    repository = SecurityDataRepository()

    result = run_alert_investigation(alert_payload=alert, llm=llm, repository=repository)
    print(result)


if __name__ == "__main__":
    main()
