#!/usr/bin/env python3
"""
Zuck Agent Analytics Tool
Analyze and generate reports from session data
"""

import json
import sys
from pathlib import Path
from typing import List
from collections import defaultdict
import argparse


def load_session(filepath: Path) -> dict:
    """Load session data"""
    with open(filepath, 'r') as f:
        return json.load(f)


def list_sessions(log_dir: Path) -> List[Path]:
    """List all session files"""
    return sorted(log_dir.glob("session_*.json"))


def generate_report(session_file: Path):
    """Generate detailed report for a session"""
    data = load_session(session_file)

    print("\n" + "=" * 80)
    print(f"ANALYTICS REPORT: {session_file.name}")
    print("=" * 80 + "\n")

    # Metadata
    metadata = data.get('metadata', {})
    print("📋 SESSION METADATA")
    print("-" * 80)
    for key, value in metadata.items():
        print(f"  {key}: {value}")

    # Summary
    print("\n📊 SUMMARY")
    print("-" * 80)
    summary = data.get('session_summary', {})
    for key, value in summary.items():
        print(f"  {key}: {value}")

    # Token usage
    print("\n🎫 TOKEN USAGE")
    print("-" * 80)
    tokens = data.get('token_usage', {})
    for key, value in tokens.items():
        print(f"  {key}: {value}")

    # Performance
    print("\n⚡ PERFORMANCE")
    print("-" * 80)
    perf = data.get('performance_metrics', {})
    for key, value in perf.items():
        print(f"  {key}: {value}")

    # Security
    print("\n🔒 SECURITY")
    print("-" * 80)
    security = data.get('security_stats', {})
    for key, value in security.items():
        print(f"  {key}: {value}")

    # Command history
    print("\n📜 COMMAND HISTORY")
    print("-" * 80)
    commands = data.get('command_history', [])
    for i, cmd in enumerate(commands, 1):
        status_emoji = {
            'success': '✅',
            'failed': '❌',
            'blocked': '🚫',
            'timeout': '⏱️',
            'error': '🚨'
        }.get(cmd['status'], '❓')

        print(f"\n{i}. {status_emoji} {cmd['command'][:60]}")
        print(f"   Status: {cmd['status']} | Time: {cmd['execution_time']:.3f}s")
        print(f"   Security: {cmd['security_level']}")
        if cmd.get('blocked_reason'):
            print(f"   Blocked: {cmd['blocked_reason']}")

    print("\n" + "=" * 80 + "\n")


def compare_sessions(session_files: List[Path]):
    """Compare multiple sessions"""
    print("\n" + "=" * 80)
    print("SESSION COMPARISON")
    print("=" * 80 + "\n")

    for session_file in session_files:
        data = load_session(session_file)
        metadata = data.get('metadata', {})
        summary = data.get('session_summary', {})
        tokens = data.get('token_usage', {})

        print(f"Session: {metadata.get('session_id')}")
        print("-" * 80)
        print(f"  Duration: {summary.get('duration')}")
        print(f"  Commands: {summary.get('total_commands')}")
        print(f"  Success Rate: {summary.get('success_rate')}")
        print(f"  Total Tokens: {tokens.get('total_tokens')}")
        print(f"  Cost: {tokens.get('estimated_cost')}")
        print()

    print("=" * 80 + "\n")


def main():
    parser = argparse.ArgumentParser(description="Zuck Agent Analytics Tool")
    parser.add_argument('--log-dir', default='logs', help='Log directory')
    parser.add_argument('--list', action='store_true', help='List all sessions')
    parser.add_argument('--report', help='Generate report for session ID')
    parser.add_argument('--compare', nargs='+', help='Compare multiple sessions')
    parser.add_argument('--latest', action='store_true', help='Report on latest session')

    args = parser.parse_args()

    log_dir = Path(args.log_dir)

    if not log_dir.exists():
        print(f"❌ Log directory not found: {log_dir}")
        sys.exit(1)

    if args.list:
        sessions = list_sessions(log_dir)
        print(f"\n📁 Found {len(sessions)} sessions:\n")
        for session in sessions:
            print(f"  • {session.name}")
        print()
        return

    if args.latest:
        sessions = list_sessions(log_dir)
        if sessions:
            generate_report(sessions[-1])
        else:
            print("❌ No sessions found")
        return

    if args.report:
        session_file = log_dir / f"session_{args.report}.json"
        if session_file.exists():
            generate_report(session_file)
        else:
            print(f"❌ Session not found: {session_file}")
        return

    if args.compare:
        session_files = [log_dir / f"session_{sid}.json" for sid in args.compare]
        valid_files = [f for f in session_files if f.exists()]

        if valid_files:
            compare_sessions(valid_files)
        else:
            print("❌ No valid session files found")
        return

    parser.print_help()


if __name__ == "__main__":
    main()