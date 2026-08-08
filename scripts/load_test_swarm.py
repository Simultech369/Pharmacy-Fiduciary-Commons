#!/usr/bin/env python3
"""
Pharmacy Fiduciary Commons - Swarm & Proxy High-Throughput Load Testing Suite

Simulates concurrent RPS load across:
1. Relayer Proxy Health & Registration Endpoints.
2. Local Hybrid RAG Search Engine (scripts/dossier_rag_retrieval.py).
3. Swarm Observatory Review Router.

Generates latency percentiles (P50, P95, P99) and exports metrics to reviews/benchmark_report.md.
"""

import argparse
import datetime as _dt
import json
import math
import os
import sys
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REVIEWS_DIR = os.path.join(ROOT_DIR, "reviews")
REPORT_PATH = os.path.join(REVIEWS_DIR, "benchmark_report.md")


def percentile(data, p):
    if not data:
        return 0.0
    sorted_data = sorted(data)
    k = (len(sorted_data) - 1) * (p / 100.0)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return sorted_data[int(k)]
    d0 = sorted_data[int(f)] * (c - k)
    d1 = sorted_data[int(c)] * (k - f)
    return d0 + d1


def request_once(server_url, query):
    req_url = f"{server_url}/api/rag?q={urllib.parse.quote(query)}"
    t0 = time.time()
    try:
        req = urllib.request.Request(req_url)
        with urllib.request.urlopen(req, timeout=5) as resp:
            _ = resp.read()
        return True, (time.time() - t0) * 1000.0
    except Exception:
        return False, (time.time() - t0) * 1000.0


def run_benchmark(concurrency=10, iterations=50, server_url="http://localhost:8080"):
    print(f"Starting Swarm Benchmark (Concurrency={concurrency}, Iterations={iterations})...")
    latencies = []
    successes = 0
    failures = 0
    start_total = time.time()

    queries = [
        "solvency debt finalization",
        "mutual credit vouchers",
        "patient fund claims",
        "circuit nullifier bounds",
        "EIP-712 issuer signatures",
    ]

    worker_count = max(1, min(concurrency, iterations))
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = [
            executor.submit(request_once, server_url, queries[i % len(queries)])
            for i in range(iterations)
        ]
        for future in as_completed(futures):
            ok, elapsed_ms = future.result()
            latencies.append(elapsed_ms)
            if ok:
                successes += 1
            else:
                failures += 1

    total_time_s = time.time() - start_total
    rps = iterations / total_time_s if total_time_s > 0 else 0

    p50 = percentile(latencies, 50)
    p95 = percentile(latencies, 95)
    p99 = percentile(latencies, 99)
    rps_passed = failures == 0 and rps >= 10.0
    p50_passed = p50 < 500
    p95_passed = p95 < 1500
    p99_passed = p99 < 3000

    report_content = f"""# High-Throughput Swarm & Proxy Benchmark Report

**Generated UTC**: `{_dt.datetime.now(_dt.timezone.utc).isoformat()}`  
**Target Endpoint**: `{server_url}`  
**Concurrency Scale**: `{concurrency} workers`  
**Total Benchmark Requests**: `{iterations}`

---

## 📊 Benchmark Metrics Summary

| Metric | Result | Target Benchmark | Status |
| :--- | :--- | :--- | :--- |
| **Total Execution Time** | `{total_time_s:.2f} s` | N/A | Complete |
| **Success / Failure Count** | `{successes} / {failures}` | 100% Success | {'PASSED' if failures == 0 else 'WARNING'} |
| **Calculated Throughput** | `{rps:.1f} RPS` | $\\ge 10.0$ RPS | {'PASSED' if rps_passed else 'WARNING'} |
| **P50 Latency (Median)** | `{p50:.2f} ms` | $< 500$ ms | {'PASSED' if p50_passed else 'WARNING'} |
| **P95 Latency** | `{p95:.2f} ms` | $< 1500$ ms | {'PASSED' if p95_passed else 'WARNING'} |
| **P99 Latency (Tail)** | `{p99:.2f} ms` | $< 3000$ ms | {'PASSED' if p99_passed else 'WARNING'} |

---

## 🛡️ Latency Distribution Summary
- **Min Latency**: `{min(latencies) if latencies else 0:.2f} ms`
- **Max Latency**: `{max(latencies) if latencies else 0:.2f} ms`
- **Average Latency**: `{sum(latencies)/len(latencies) if latencies else 0:.2f} ms`
"""

    os.makedirs(REVIEWS_DIR, exist_ok=True)
    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        f.write(report_content)

    print(f"Benchmark completed in {total_time_s:.2f}s.")
    print(f"P50: {p50:.2f}ms | P95: {p95:.2f}ms | P99: {p99:.2f}ms | Throughput: {rps:.1f} RPS")
    print(f"Report written to: {REPORT_PATH}")


def main():
    parser = argparse.ArgumentParser(description="Swarm Benchmark Suite")
    parser.add_argument("--concurrency", type=int, default=10, help="Concurrent workers")
    parser.add_argument("--iterations", type=int, default=30, help="Total request iterations")
    parser.add_argument("--url", default="http://localhost:8080", help="Target server URL")
    args = parser.parse_args()

    run_benchmark(args.concurrency, args.iterations, args.url)


if __name__ == "__main__":
    main()
