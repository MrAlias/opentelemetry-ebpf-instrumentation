#!/usr/bin/env python3
"""Replay a PR-description checker against recent maintainer PRs."""

import argparse
import concurrent.futures
import dataclasses
import datetime as dt
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from collections import Counter
from typing import Optional


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CHECKER = REPOSITORY_ROOT / "scripts/check-pr-description.py"
DEFAULT_MAINTAINERS_FILE = REPOSITORY_ROOT / "CONTRIBUTING.md"

SEARCH_QUERY = """
query($searchQuery: String!, $cursor: String) {
  search(query: $searchQuery, type: ISSUE, first: 100, after: $cursor) {
    issueCount
    pageInfo {
      hasNextPage
      endCursor
    }
    nodes {
      ... on PullRequest {
        number
        url
        title
        body
        createdAt
        author {
          login
        }
      }
    }
  }
}
"""

REASON_PATTERNS = (
    ("heading_limit", "section headings"),
    ("character_limit", "characters of prose"),
    ("sentence_length", "sentences average"),
    ("long_word_ratio", "of the words have"),
    ("boilerplate_phrase", "generated boilerplate phrasing"),
    ("filler_words", "abstract filler words"),
)


@dataclasses.dataclass(frozen=True)
class PullRequest:
    maintainer: str
    number: int
    url: str
    title: str
    body: str
    created_at: str


@dataclasses.dataclass(frozen=True)
class CheckResult:
    pull_request: PullRequest
    passed: bool
    reasons: tuple[str, ...]
    findings: tuple[str, ...]


def parse_args() -> argparse.Namespace:
    today = dt.datetime.now(dt.timezone.utc).date()
    parser = argparse.ArgumentParser(
        description=(
            "Run a local PR-description checker against the current bodies of "
            "maintainer-authored PRs."
        )
    )
    parser.add_argument(
        "--checker",
        type=Path,
        default=DEFAULT_CHECKER,
        help=f"checker to run (default: {DEFAULT_CHECKER})",
    )
    parser.add_argument(
        "--repo",
        help="GitHub repository as OWNER/REPO (default: infer from upstream or origin)",
    )
    parser.add_argument(
        "--since",
        type=parse_date,
        default=today - dt.timedelta(days=90),
        metavar="YYYY-MM-DD",
        help="include PRs created on or after this date (default: 90 days ago)",
    )
    parser.add_argument(
        "--until",
        type=parse_date,
        default=today,
        metavar="YYYY-MM-DD",
        help="include PRs created on or before this date (default: today, UTC)",
    )
    parser.add_argument(
        "--maintainers-file",
        type=Path,
        default=DEFAULT_MAINTAINERS_FILE,
        help=(
            "file containing the Maintainers section "
            f"(default: {DEFAULT_MAINTAINERS_FILE})"
        ),
    )
    parser.add_argument(
        "--maintainer",
        action="append",
        default=[],
        metavar="LOGIN",
        help="analyze this GitHub login; repeat to override automatic discovery",
    )
    parser.add_argument(
        "--jobs",
        type=positive_int,
        default=min(8, os.cpu_count() or 1),
        help="checker processes to run concurrently (default: up to 8)",
    )
    parser.add_argument(
        "--show-failures",
        action="store_true",
        help="print every rejected PR and the checker's findings",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="write the complete report as JSON",
    )
    args = parser.parse_args()

    if args.since > args.until:
        parser.error("--since must not be later than --until")
    return args


def parse_date(value: str) -> dt.date:
    try:
        return dt.date.fromisoformat(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            f"invalid date {value!r}; expected YYYY-MM-DD"
        ) from error


def positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError(f"invalid integer: {value!r}") from error
    if parsed < 1:
        raise argparse.ArgumentTypeError("value must be at least 1")
    return parsed


def github_repository(url: str) -> Optional[str]:
    match = re.search(r"github\.com[:/]([^/]+/[^/]+?)(?:\.git)?$", url.strip())
    return match.group(1) if match else None


def infer_repository() -> str:
    for remote in ("upstream", "origin"):
        process = subprocess.run(
            ["git", "-C", str(REPOSITORY_ROOT), "remote", "get-url", remote],
            check=False,
            capture_output=True,
            text=True,
        )
        if process.returncode == 0:
            repository = github_repository(process.stdout)
            if repository:
                return repository
    raise RuntimeError("cannot infer a GitHub repository; pass --repo OWNER/REPO")


def read_maintainers(path: Path) -> list[str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise RuntimeError(f"cannot read maintainers file {path}: {error}") from error

    in_section = False
    maintainers = []
    for line in lines:
        if line.strip() == "### Maintainers":
            in_section = True
            continue
        if in_section and re.match(r"^#{1,3}\s", line):
            break
        if not in_section:
            continue

        if not re.match(r"^\s*[*-]\s", line):
            continue
        match = re.search(r"https://github\.com/([A-Za-z0-9-]+)", line)
        if match and match.group(1) not in maintainers:
            maintainers.append(match.group(1))

    if not maintainers:
        raise RuntimeError(
            f"no GitHub logins found in the Maintainers section of {path}"
        )
    return maintainers


def gh_graphql(search_query: str, cursor: Optional[str]) -> dict:
    command = [
        "gh",
        "api",
        "graphql",
        "-f",
        f"query={SEARCH_QUERY}",
        "-F",
        f"searchQuery={search_query}",
    ]
    if cursor:
        command.extend(("-F", f"cursor={cursor}"))

    process = subprocess.run(command, check=False, capture_output=True, text=True)
    if process.returncode != 0:
        detail = process.stderr.strip() or process.stdout.strip()
        raise RuntimeError(f"GitHub query failed: {detail}")
    try:
        return json.loads(process.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError("GitHub returned invalid JSON") from error


def fetch_pull_requests(
    repository: str,
    maintainer: str,
    since: dt.date,
    until: dt.date,
) -> list[PullRequest]:
    query = (
        f"repo:{repository} is:pr author:{maintainer} "
        f"created:{since.isoformat()}..{until.isoformat()}"
    )
    pull_requests = []
    cursor = None

    while True:
        response = gh_graphql(query, cursor)
        try:
            search = response["data"]["search"]
        except (KeyError, TypeError) as error:
            raise RuntimeError(f"unexpected GitHub response: {response}") from error

        if search["issueCount"] > 1000:
            raise RuntimeError(
                f"{maintainer} has more than GitHub Search's 1,000-result limit; "
                "use a narrower date range"
            )

        for node in search["nodes"]:
            if not node:
                continue
            pull_requests.append(
                PullRequest(
                    maintainer=maintainer,
                    number=node["number"],
                    url=node["url"],
                    title=node["title"],
                    body=node["body"] or "",
                    created_at=node["createdAt"],
                )
            )

        page_info = search["pageInfo"]
        if not page_info["hasNextPage"]:
            break
        cursor = page_info["endCursor"]

    return pull_requests


def extract_findings(output: str) -> tuple[str, ...]:
    findings = []
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith("- "):
            findings.append(stripped[2:])
    if findings:
        return tuple(findings)
    output = output.strip()
    return (output,) if output else ("checker rejected the description",)


def classify_findings(findings: tuple[str, ...]) -> tuple[str, ...]:
    reasons = set()
    for finding in findings:
        reason = next(
            (name for name, marker in REASON_PATTERNS if marker in finding),
            "other",
        )
        reasons.add(reason)
    return tuple(sorted(reasons))


def check_pull_request(checker: Path, pull_request: PullRequest) -> CheckResult:
    environment = os.environ.copy()
    environment.pop("PR_BODY", None)
    process = subprocess.run(
        [sys.executable, str(checker)],
        input=pull_request.body,
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )
    if process.returncode == 0:
        return CheckResult(pull_request, True, (), ())
    if process.returncode != 1:
        detail = process.stderr.strip() or process.stdout.strip()
        raise RuntimeError(
            f"checker exited with {process.returncode} for {pull_request.url}: {detail}"
        )

    findings = extract_findings(process.stdout or process.stderr)
    return CheckResult(
        pull_request,
        False,
        classify_findings(findings),
        findings,
    )


def analyze(
    checker: Path, pull_requests: list[PullRequest], jobs: int
) -> list[CheckResult]:
    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as executor:
        futures = [
            executor.submit(check_pull_request, checker, pull_request)
            for pull_request in pull_requests
        ]
        results = [future.result() for future in futures]
    return sorted(
        results,
        key=lambda result: (
            result.pull_request.maintainer.lower(),
            result.pull_request.created_at,
            result.pull_request.number,
        ),
    )


def percentage(failed: int, total: int) -> str:
    return f"{100 * failed / total:.1f}%" if total else "0.0%"


def result_report(
    repository: str,
    checker: Path,
    since: dt.date,
    until: dt.date,
    queried_at: str,
    maintainers: list[str],
    results: list[CheckResult],
) -> dict:
    rows = []
    for maintainer in maintainers:
        selected = [
            result
            for result in results
            if result.pull_request.maintainer == maintainer
        ]
        failed = sum(not result.passed for result in selected)
        rows.append(
            {
                "maintainer": maintainer,
                "failed": failed,
                "total": len(selected),
                "failure_rate": failed / len(selected) if selected else 0,
            }
        )

    failed_results = [result for result in results if not result.passed]
    reason_counts = Counter(
        reason for result in failed_results for reason in result.reasons
    )
    combination_counts = Counter(
        "+".join(result.reasons) for result in failed_results
    )
    return {
        "repository": repository,
        "checker": str(checker),
        "since": since.isoformat(),
        "until": until.isoformat(),
        "queried_at": queried_at,
        "maintainers": rows,
        "summary": {
            "failed": len(failed_results),
            "total": len(results),
            "failure_rate": len(failed_results) / len(results) if results else 0,
            "reasons": dict(sorted(reason_counts.items())),
            "reason_combinations": dict(sorted(combination_counts.items())),
        },
        "pull_requests": [
            {
                "maintainer": result.pull_request.maintainer,
                "number": result.pull_request.number,
                "url": result.pull_request.url,
                "title": result.pull_request.title,
                "created_at": result.pull_request.created_at,
                "passed": result.passed,
                "reasons": list(result.reasons),
                "findings": list(result.findings),
            }
            for result in results
        ],
    }


def print_report(report: dict, show_failures: bool) -> None:
    print(f"Repository: {report['repository']}")
    print(f"Checker: {report['checker']}")
    print(f"Created: {report['since']} through {report['until']}")
    print(f"Bodies: current as queried at {report['queried_at']}")
    print()

    rows = report["maintainers"]
    login_width = max(len("Maintainer"), *(len(row["maintainer"]) for row in rows))
    print(f"{'Maintainer':<{login_width}}  {'Failed':>6}  {'Total':>5}  {'Rate':>6}")
    print(f"{'-' * login_width}  {'-' * 6}  {'-' * 5}  {'-' * 6}")
    for row in rows:
        print(
            f"{row['maintainer']:<{login_width}}  {row['failed']:>6}  "
            f"{row['total']:>5}  {percentage(row['failed'], row['total']):>6}"
        )

    summary = report["summary"]
    print(
        f"{'All':<{login_width}}  {summary['failed']:>6}  "
        f"{summary['total']:>5}  "
        f"{percentage(summary['failed'], summary['total']):>6}"
    )

    print("\nFailure reasons (a PR may have more than one):")
    if summary["reasons"]:
        for reason, count in summary["reasons"].items():
            print(f"  {reason}: {count}")
    else:
        print("  none")

    print("\nFailure reason combinations:")
    if summary["reason_combinations"]:
        for combination, count in summary["reason_combinations"].items():
            print(f"  {combination}: {count}")
    else:
        print("  none")

    if not show_failures:
        return

    print("\nRejected pull requests:")
    failed = [item for item in report["pull_requests"] if not item["passed"]]
    if not failed:
        print("  none")
        return
    for item in failed:
        reasons = ", ".join(item["reasons"])
        print(
            f"  #{item['number']} {item['maintainer']} {item['created_at'][:10]} "
            f"[{reasons}] {item['url']}"
        )
        for finding in item["findings"]:
            print(f"    - {finding}")


def main() -> int:
    args = parse_args()
    if shutil.which("gh") is None:
        raise RuntimeError("gh is required and must be available on PATH")

    checker = args.checker.resolve()
    if not checker.is_file():
        raise RuntimeError(f"checker does not exist: {checker}")

    repository = args.repo or infer_repository()
    if not re.fullmatch(r"[^/\s]+/[^/\s]+", repository):
        raise RuntimeError(f"invalid repository {repository!r}; expected OWNER/REPO")

    maintainers = args.maintainer or read_maintainers(args.maintainers_file)
    queried_at = (
        dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
    pull_requests = []
    for maintainer in maintainers:
        print(f"Fetching PRs by {maintainer}...", file=sys.stderr)
        pull_requests.extend(
            fetch_pull_requests(repository, maintainer, args.since, args.until)
        )

    print(f"Checking {len(pull_requests)} PR descriptions...", file=sys.stderr)
    results = analyze(checker, pull_requests, args.jobs)
    report = result_report(
        repository,
        checker,
        args.since,
        args.until,
        queried_at,
        maintainers,
        results,
    )
    if args.json_output:
        json.dump(report, sys.stdout, indent=2)
        print()
    else:
        print_report(report, args.show_failures)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except RuntimeError as error:
        print(f"error: {error}", file=sys.stderr)
        sys.exit(2)
