"""Imported by the isolated runtime fixture when AEGIS_BENCHMARK_REPORT is set."""
from concurrent.futures import ThreadPoolExecutor
import http.client
import math
import time


def measure(port, requests=64000, concurrency=16):
    def client(count):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        samples = []
        try:
            for _ in range(count):
                start = time.perf_counter_ns()
                conn.request("GET", "/healthy", headers={"Host": "container.example.com", "User-Agent": "Aegis-benchmark"})
                response = conn.getresponse()
                body = response.read()
                samples.append((time.perf_counter_ns() - start) / 1e6)
                if response.status != 200 or body != b"container verified upstream":
                    raise RuntimeError("Benchmark returned an unexpected response")
        finally:
            conn.close()
        return samples

    client(50)  # Warm up connections and snapshot code before measuring.
    start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        results = list(pool.map(client, [requests // concurrency] * concurrency))
    seconds = time.perf_counter() - start
    samples = sorted(value for part in results for value in part)
    percentile = lambda fraction: samples[min(len(samples) - 1, math.ceil(len(samples) * fraction) - 1)]
    return {"requests": len(samples), "concurrency": concurrency, "seconds": round(seconds, 3), "requests_per_second": round(len(samples) / seconds, 1), "p50_ms": round(percentile(.5), 3), "p95_ms": round(percentile(.95), 3), "p99_ms": round(percentile(.99), 3)}
