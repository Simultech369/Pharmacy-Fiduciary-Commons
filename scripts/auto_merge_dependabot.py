#!/usr/bin/env python3
"""Read-only branch hygiene reporter for public collaborator preparation.

This script intentionally does not merge, reset, install packages, push, or delete
branches. It exists to keep Dependabot/feature branch reconciliation auditable
without changing local or remote repository state.
"""

from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass
from typing import Iterable


EXPECTED_REMOTE_BRANCHES = (
    "origin/dependabot/github_actions/actions/checkout-7",
    "origin/dependabot/github_actions/actions/setup-node-7",
    "origin/dependabot/npm_and_yarn/ethers-6.17.0",
    "origin/dependabot/npm_and_yarn/hardhat-3.9.0",
    "origin/dependabot/npm_and_yarn/nomicfoundation/hardhat-ethers-4.0.13",
    "origin/dependabot/npm_and_yarn/nomicfoundation/hardhat-verify-3.0.20",
    "origin/dependabot/npm_and_yarn/openzeppelin/contracts-5.6.1",
    "origin/feature/roadmap-and-drafts",
)


DEFERRED_DEPENDENCY_NOTES = {
    "origin/dependabot/npm_and_yarn/ethers-6.17.0": "defer until lockfile-only update passes the full verifier",
    "origin/dependabot/npm_and_yarn/hardhat-3.9.0": "defer; Hardhat major/runtime migration needs a dedicated branch",
    "origin/dependabot/npm_and_yarn/nomicfoundation/hardhat-ethers-4.0.13": "defer with Hardhat 3 migration bundle",
    "origin/dependabot/npm_and_yarn/nomicfoundation/hardhat-verify-3.0.20": "defer with Hardhat 3 migration bundle",
    "origin/dependabot/npm_and_yarn/openzeppelin/contracts-5.6.1": "defer; OpenZeppelin 5 import/API changes need contract review",
}


@dataclass(frozen=True)
class BranchStatus:
    branch: str
    status: str
    note: str


def run_git(args: Iterable[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        check=False,
        capture_output=True,
        text=True,
    )


def current_remote_branches() -> set[str]:
    result = run_git(["branch", "-r", "--format", "%(refname:short)"])
    if result.returncode != 0:
        return set()

    return {
        line.strip()
        for line in result.stdout.splitlines()
        if line.strip() and " -> " not in line and line.strip() not in {"origin", "origin/HEAD"}
    }


def branch_is_ancestor(branch: str) -> bool:
    result = run_git(["merge-base", "--is-ancestor", branch, "HEAD"])
    return result.returncode == 0


def summarize_branch(branch: str, known_remote_refs: set[str]) -> BranchStatus:
    if branch not in known_remote_refs:
        return BranchStatus(
            branch=branch,
            status="absent-from-local-remote-refs",
            note="already cleaned up locally or not fetched; confirm with git ls-remote before quoting public branch counts",
        )

    if branch_is_ancestor(branch):
        return BranchStatus(
            branch=branch,
            status="included-in-local-head",
            note="safe to close/delete remote branch after local HEAD is pushed and verified on origin/main",
        )

    return BranchStatus(
        branch=branch,
        status="not-in-local-head",
        note=DEFERRED_DEPENDENCY_NOTES.get(branch, "review manually before merging"),
    )


def main() -> int:
    top_level = run_git(["rev-parse", "--show-toplevel"])
    if top_level.returncode != 0:
        sys.stderr.write("FAILED: run from inside a Git repository.\n")
        return 2

    status = run_git(["status", "--short", "--branch"])
    print("BRANCH HYGIENE REPORT - READ ONLY")
    print("=" * 40)
    print(status.stdout.strip())
    print()

    known_remote_refs = current_remote_branches()
    print("Remote branch reconciliation:")
    for branch in EXPECTED_REMOTE_BRANCHES:
        item = summarize_branch(branch, known_remote_refs)
        print(f"- {item.branch}: {item.status} - {item.note}")

    discovered_extras = sorted(
        branch
        for branch in known_remote_refs
        if branch not in EXPECTED_REMOTE_BRANCHES and branch != "origin/main"
    )
    if discovered_extras:
        print()
        print("Additional remote-tracking refs:")
        for branch in discovered_extras:
            print(f"- {branch}: review manually")

    print()
    print("Recommended public-review sequence:")
    print("1. Push the verified local main if origin/main is still behind.")
    print("2. Close/delete side branches already included in origin/main.")
    print("3. Keep deferred package upgrades open only if they have a named migration owner.")
    print("4. Re-run python scripts/verify_all.py after branch cleanup and quote that receipt.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
