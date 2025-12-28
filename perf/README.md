# Performance Harness

This harness runs repeatable load tests in containers so CI can detect latency/throughput regressions without installing tools locally.

## Layout
- `compose.yaml` — spins up ExfilGuard, a simple upstream server, and a k6 client.
- `Dockerfile.exfilguard` — builds a release ExfilGuard binary into a small runtime image.
- `config/` — minimal clients/policies plus base settings for the harness.
- `scripts/http-load.js` — k6 scenario driving HTTP/1.1 load through the proxy; results are written under `/results`.

## Running locally
```bash
cd perf
docker compose build exfilguard
docker compose up --abort-on-container-exit --exit-code-from client exfilguard upstream client
docker compose down
```

Results are written to `perf/results/summary.json`. Adjust rate/duration/VUs via environment (`RATE`, `DURATION`, `VUS`, `MAX_VUS`, `TARGET`) before running.

After a run, `perf/run.sh` also renders an HTML report at `perf/results/summary.html` using `k6 report`.

### Ramping load (finding the knee)
By default the k6 client ramps arrival rate to push the proxy: start `RAMP_START_RATE` (default 500 rps), increase by `RAMP_STEP` (default 250 rps) for `RAMP_STAGES` stages (default 4), each lasting `RAMP_STAGE_DURATION` (default 30s). Disable ramping and stick to a steady rate by setting `RAMP=0`.

### Time-series dashboard export
The k6 web dashboard is enabled and exported to `perf/results/dashboard.html` (no live port, `K6_WEB_DASHBOARD_PORT=-1`). Adjust snapshot granularity with `K6_WEB_DASHBOARD_PERIOD` (default 2s). This HTML contains over-time plots (latency, RPS, failures) for CI artifacts; the reporter-generated `summary.html` remains for quick aggregates.
