# scripts/comment_report.py
import argparse
import os
from pathlib import Path

import requests


def post_pr_comment(repo: str, pr_number: str, body: str, token: str) -> None:
    url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
    r = requests.post(
        url,
        headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
        json={"body": body},
        timeout=30,
    )
    r.raise_for_status()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--report", required=True)
    ap.add_argument("--pr", required=True)
    ap.add_argument("--repo", required=True)
    args = ap.parse_args()

    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        print("No GITHUB_TOKEN; skipping comment.")
        return

    report = Path(args.report).read_text(encoding="utf-8")
    body = "## 🔐 Security Gate Report\n\n" + report[:60000]  # GitHub comment limit safety
    post_pr_comment(args.repo, args.pr, body, token)
    print("Posted PR comment.")


if __name__ == "__main__":
    main()
