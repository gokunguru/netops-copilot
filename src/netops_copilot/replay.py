"""Runs recorded on real systems (the Muse Spark API, a real Cisco router), played back.

`netops-copilot ... --record replays/<name>.json` saves every pipeline step with its timing,
the full result and the approval outcome. The public demo cannot call the paid API or reach a
lab router, so it plays these recordings back, read-only, clearly labelled as recordings.
"""

import json
import os
import time
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, Field, ValidationError

from netops_copilot.models import RunResult, Step

DEFAULT_DIR = Path(os.getenv("NETOPS_REPLAYS") or Path(__file__).resolve().parents[2] / "replays")
MAX_PAUSE = 1.5  # seconds: real model latency is kept, but never makes a viewer wait long


class RecordedStep(Step):
    t: float = Field(ge=0)  # seconds since the run started

    def as_step(self) -> Step:
        return Step(**self.model_dump(exclude={"t"}))


class Outcome(BaseModel):
    decision: str = ""  # approved, rejected, failed, or "" (audit, answer)
    change: str = ""
    where: str = ""
    rollback: dict[str, list[str]] = Field(default_factory=dict)
    detail: str = ""


class Replay(BaseModel):
    name: str = ""
    title: str
    recorded: str
    model: str
    target: str
    request: str
    duration: float = 0
    steps: list[RecordedStep]
    result: RunResult
    outcome: Outcome = Field(default_factory=Outcome)


class Recorder:
    """on_step callback that keeps every step with its time offset."""

    def __init__(self) -> None:
        self.start = time.monotonic()
        self.steps: list[RecordedStep] = []

    def __call__(self, step: Step) -> None:
        self.steps.append(RecordedStep(**step.model_dump(), t=round(time.monotonic() - self.start, 2)))

    def save(self, path: str | Path, *, title: str, model: str, target: str, result: RunResult,
             outcome: Outcome) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        data = Replay(title=title, recorded=datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
                      model=model, target=target, request=result.request,
                      duration=round(time.monotonic() - self.start, 1), steps=self.steps,
                      result=result, outcome=outcome)
        path.write_text(json.dumps(data.model_dump(mode="json", exclude={"name"}), indent=1) + "\n")
        return path


def load_all(directory: str | Path = DEFAULT_DIR) -> list[Replay]:
    """Every valid recording, sorted by file name. A broken file is skipped, never fatal."""
    found = []
    for path in sorted(Path(directory).glob("*.json")):
        try:
            found.append(Replay(**json.loads(path.read_text()), name=path.stem))
        except (ValidationError, ValueError, TypeError):
            continue
    return found
