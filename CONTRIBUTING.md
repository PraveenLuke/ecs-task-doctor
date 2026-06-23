# Contributing to ecs-task-doctor

## Origin

`ecs-task-doctor` was designed and originally authored by **Praveen Rajkoilraj** ([@praveenrajkoilraj](https://github.com/praveenrajkoilraj)).

If you fork this project or build on it, the MIT License requires you to preserve the copyright notice in [LICENSE](LICENSE). That notice names the original author and must remain intact in all copies and derivative works.

## How to contribute

Bug reports, feature ideas, and pull requests are welcome. Before opening a PR:

1. **Open an issue first** for anything larger than a typo fix, so the change can be discussed before you invest time writing code.
2. **Keep PRs focused** — one feature or fix per PR. Split unrelated changes.
3. **All tests must pass** — run `pytest tests/ -v` and make sure nothing regresses.
4. **Add tests** for any new diagnoser pattern or aggregator change. The test coverage standard is: every new `FindingType` value should have at least one positive and one negative test case.
5. **No new dependencies** without discussion. The dependency footprint is intentionally small (boto3, rich, click).

## Adding a new diagnoser pattern

- **New ECS service event pattern** → add a row to `_EVENT_RULES` in [ecs_doctor/diagnosers/events.py](ecs_doctor/diagnosers/events.py)
- **New stop code or exit code** → add a row to `_TASK_STOP_CODE_MAP` or a branch to `_classify_container` in [ecs_doctor/diagnosers/stop_reasons.py](ecs_doctor/diagnosers/stop_reasons.py)
- **New log crash signature** → add a row to `CRASH_PATTERNS` in [ecs_doctor/diagnosers/logs.py](ecs_doctor/diagnosers/logs.py)
- **New ALB target health reason** → add a row to `_REASON_MAP` in [ecs_doctor/diagnosers/alb_health.py](ecs_doctor/diagnosers/alb_health.py)

If you add a new `FindingType`, also add a corresponding entry to `_HYPOTHESIS` in [ecs_doctor/aggregator.py](ecs_doctor/aggregator.py) so it is scored and surfaced in the root cause report.

## Development setup

```bash
git clone https://github.com/praveenrajkoilraj/ecs-task-doctor
cd ecs-task-doctor
pip install -e ".[dev]"
pytest tests/ -v
```

Python 3.12 or later is required.

## Code style

- Follow existing patterns — the diagnosers are intentionally data-driven (rules tables, not long if-chains).
- No new comments that describe *what* the code does — only add a comment when the *why* is non-obvious.
- Run `python3 -m pytest tests/` before pushing. CI will reject PRs with failing tests.

## License

By submitting a pull request you agree that your contribution will be licensed under the [MIT License](LICENSE), with copyright retained by the original author and contributors as recorded in the git history.
