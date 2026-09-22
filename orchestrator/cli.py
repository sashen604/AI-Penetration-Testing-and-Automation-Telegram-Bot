"""CLI entrypoint, useful before the web/bot layers are wired up.

Usage:
  python -m orchestrator.cli scan example.com --scope scope.txt
  python -m orchestrator.cli jobs
  python -m orchestrator.cli report <job_id>
  python -m orchestrator.cli verdict <finding_id> true_positive|false_positive
"""
import argparse
import asyncio
import logging
import sys

from orchestrator import db
from orchestrator.ai.triage import record_lesson_from_verdict
from orchestrator.pipeline import run_pipeline
from orchestrator.report import generate_report

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")


def main():
    db.init_db()
    parser = argparse.ArgumentParser(prog="bugbounty")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_scan = sub.add_parser("scan", help="Run the full pipeline against a target")
    p_scan.add_argument("domain")
    p_scan.add_argument("--scope", help="Path to a scope file", default=None)

    sub.add_parser("jobs", help="List recent jobs")

    p_report = sub.add_parser("report", help="Generate a markdown report for a job")
    p_report.add_argument("job_id", type=int)

    p_findings = sub.add_parser("findings", help="List findings for a target")
    p_findings.add_argument("target")

    p_verdict = sub.add_parser("verdict", help="Record a human verdict on a finding")
    p_verdict.add_argument("finding_id", type=int)
    p_verdict.add_argument("verdict", choices=["true_positive", "false_positive"])

    args = parser.parse_args()

    if args.cmd == "scan":
        scope_text = ""
        if args.scope:
            scope_text = open(args.scope).read()
        job_id = db.create_job(args.domain)
        print(f"Starting job {job_id} for {args.domain}...")
        result = asyncio.run(run_pipeline(job_id, args.domain, scope_text))
        print(result["summary"])
        path = generate_report(job_id)
        print(f"Report written to {path}")

    elif args.cmd == "jobs":
        for j in db.list_jobs():
            print(f"#{j['id']:>4} {j['status']:<8} {j['target']:<30} {j['created_at']}  {j['summary']}")

    elif args.cmd == "report":
        path = generate_report(args.job_id)
        print(f"Report written to {path}" if path else "Job not found")

    elif args.cmd == "findings":
        for f in db.list_findings(target=args.target):
            print(f"#{f['id']:>4} [{f['severity']:<8}] {f['tool']:<8} {f['verdict']:<15} {f['title']} -> {f['matched_url']}")

    elif args.cmd == "verdict":
        f = next((x for x in db.list_findings(limit=5000) if x["id"] == args.finding_id), None)
        if not f:
            print("Finding not found")
            sys.exit(1)
        record_lesson_from_verdict(args.finding_id, f["kind"], f["title"], args.verdict)
        print(f"Recorded {args.verdict} for finding #{args.finding_id} (kind={f['kind']})")


if __name__ == "__main__":
    main()
