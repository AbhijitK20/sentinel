#!/usr/bin/env python3
"""Sentinel Benchmark Suite — Compare speed against competitors."""

import subprocess
import sys
import time
from pathlib import Path


def benchmark_sentinel(target: str) -> float:
    """Benchmark sentinel scan."""
    start = time.perf_counter()
    result = subprocess.run(
        [sys.executable, "-m", "sentinel", "scan", target, "--format", "json"],
        capture_output=True,
        text=True,
        timeout=120,
    )
    elapsed = time.perf_counter() - start
    return elapsed


def benchmark_ruff(target: str) -> float:
    """Benchmark ruff check."""
    start = time.perf_counter()
    result = subprocess.run(
        ["ruff", "check", target, "--output-format=json"],
        capture_output=True,
        text=True,
        timeout=120,
    )
    elapsed = time.perf_counter() - start
    return elapsed


def benchmark_bandit(target: str) -> float:
    """Benchmark bandit scan."""
    start = time.perf_counter()
    result = subprocess.run(
        ["bandit", "-r", target, "-f", "json", "-q"],
        capture_output=True,
        text=True,
        timeout=120,
    )
    elapsed = time.perf_counter() - start
    return elapsed


def benchmark_pylint(target: str) -> float:
    """Benchmark pylint."""
    start = time.perf_counter()
    result = subprocess.run(
        ["pylint", target, "--output-format=json", "--disable=all", "--enable=E"],
        capture_output=True,
        text=True,
        timeout=300,
    )
    elapsed = time.perf_counter() - start
    return elapsed


def count_python_files(target: str) -> int:
    """Count Python files in target directory."""
    target_path = Path(target)
    if target_path.is_file():
        return 1
    return len(list(target_path.rglob("*.py")))


def format_time(seconds: float) -> str:
    """Format time in human-readable format."""
    if seconds < 1:
        return f"{seconds*1000:.0f}ms"
    elif seconds < 60:
        return f"{seconds:.1f}s"
    else:
        return f"{seconds/60:.1f}min"


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    target = str(Path(target).resolve())

    print(f"\n{'='*60}")
    print(f"  Sentinel Benchmark Suite")
    print(f"{'='*60}")
    print(f"  Target: {target}")

    file_count = count_python_files(target)
    print(f"  Files: {file_count} Python files")
    print(f"{'='*60}\n")

    results = {}

    # Benchmark each tool
    tools = [
        ("Sentinel", benchmark_sentinel),
        ("Ruff", benchmark_ruff),
        ("Bandit", benchmark_bandit),
    ]

    # Only benchmark pylint if it's installed
    try:
        subprocess.run(["pylint", "--version"], capture_output=True, timeout=5)
        tools.append(("Pylint", benchmark_pylint))
    except (FileNotFoundError, subprocess.TimeoutExpired):
        print("  [skip] Pylint not installed")

    for name, bench_func in tools:
        try:
            print(f"  Running {name}...", end="", flush=True)
            elapsed = bench_func(target)
            results[name] = elapsed
            print(f" {format_time(elapsed)}")
        except subprocess.TimeoutExpired:
            print(f" TIMEOUT (>{120}s)")
            results[name] = float("inf")
        except FileNotFoundError:
            print(f" not installed")
            results[name] = None

    # Print results
    print(f"\n{'='*60}")
    print(f"  Results ({file_count} files)")
    print(f"{'='*60}")

    # Sort by time (fastest first)
    sorted_results = sorted(
        [(k, v) for k, v in results.items() if v is not None],
        key=lambda x: x[1],
    )

    if sorted_results:
        fastest = sorted_results[0][1]
        print(f"  {'Tool':<15} {'Time':<12} {'Relative':<12} {'Speedup':<10}")
        print(f"  {'-'*49}")
        for name, elapsed in sorted_results:
            if elapsed == float("inf"):
                print(f"  {name:<15} {'TIMEOUT':<12}")
                continue
            relative = elapsed / fastest if fastest > 0 else 1
            speedup = fastest / elapsed if elapsed > 0 else 0
            print(
                f"  {name:<15} {format_time(elapsed):<12} {relative:.1f}x{'':<8} {speedup:.1f}x"
            )

    print(f"\n{'='*60}")
    print(f"  Benchmark complete")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
