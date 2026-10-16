# HTTP/2 benchmarks

`perf/h2/run.py` runs the `h2-perf` example in local Docker containers, using
`tc netem` to set bandwidth and delay. `h2-perf` runs the client, upstream server,
and ExfilGuard proxy using helpers from `tests/support/`.
Run the benchmarks on an idle Linux machine.

Build on the same architecture as the Docker daemon:

```sh
cargo build --locked --release --example h2-perf
docker build -t exfilguard-h2-perf-tools perf/h2
python3 perf/h2/run.py --profile smoke --output target/perf/smoke.json
python3 perf/h2/run.py --profile screen --windows 4/16 --fail-fast --output target/perf/4-16.json
python3 perf/h2/run.py --profile screen --windows 8/32 --fail-fast --output target/perf/8-32.json
python3 perf/h2/run.py --profile screen --windows 16/32 --fail-fast --output target/perf/16-32.json
python3 perf/h2/run.py --profile screen --windows 32/64 --fail-fast --output target/perf/32-64.json
python3 perf/h2/run.py --profile screen --windows 32/64 --tcp-initial-window 0 --output target/perf/32-64-startup.json
python3 perf/h2/run.py --profile full --windows 32/64 --output target/perf/full.json
python3 perf/h2/run.py --profile readers --windows 32/64 --seconds 30 --output target/perf/readers.json
python3 perf/h2/run.py --profile cold --windows baseline --output target/perf/cold-baseline.json
```

Choose the smallest HTTP/2 receive windows that meet the throughput criteria.
`--windows baseline` uses the old 65,535-byte limits with the current binary.
`--binary PATH` selects a different `h2-perf` build. Timing defaults are
2 seconds warmup, 5 seconds measured, and five repetitions; adjust them with
`--warmup`, `--seconds`, and
`--repetitions`. A full run takes roughly 90 minutes.

To repeat one throughput case, use
`--case 1000/100/downstream/upload/8`.

## Network setup

```text
client (10.221.1.2) -- proxy/router (.1.3 / .2.3) -- upstream server (10.221.2.2)
```

Direct connections pass through the middle container using IP routing. Proxy
connections use CONNECT with TLS inspection and the same HTTP version on both
connections. Two internal Docker bridges use `10.221.1.0/24` and `10.221.2.0/24`;
these subnets must be available. Run one benchmark at a time.

Containers receive `NET_ADMIN` for their own interfaces. Network changes stay
inside them. A temporary volume holds the CA and logs. Cleanup runs on completion,
failure, and Ctrl-C. After SIGKILL or host failure, inspect resources with the
`exfilguard-h2-` prefix recorded in the report before removing leftovers.

TSO/GSO/GRO and TCP metric caching are disabled. TCP socket buffers start at
32 MiB with 64 MiB autotuning maxima; netem queues have 262,144 packet slots.
Throughput routes use initial TCP congestion and receive windows of 16,384
segments at 1 Gbit/s and 2,048 at 100 Mbit/s, covering the bandwidth-delay product
with headroom during the short warmup.
This reduces the effect of TCP startup on the HTTP/2 throughput measurements.
Repeat the tests with `--tcp-initial-window 0` to check performance with the
kernel's default TCP initial windows. Include valid failures from both
configurations when choosing defaults. The `cold` profile always uses the
kernel defaults.

Each direction is rate-limited. Delay is applied between the proxy and upstream
server, between the client and proxy, or divided between the two paths. A UDP echo
endpoint measures RTT with a monotonic clock. The minimum RTT must match the
configured delay within 5 ms or 10%, whichever is larger. Calibration allows
three batches of ten probes and records every sample, including
neighbour-discovery delays and scheduling jitter.

The test resolver allows `origin.perf.test` to reach the upstream server's private
address. Keep `h2-perf` confined to the benchmark networks.
The upstream server generates 16 KiB chunks in memory, and receivers validate
the contents. Cache is disabled. Throughput endpoints advertise 128 MiB per stream
and 256 MiB per connection. The `readers` profile uses 65,535-byte stream windows
at the receiving endpoint so that pausing a reader quickly stops the proxy from
sending.

## Measurements and acceptance

`full` covers 1 Gbit/s at 0, 20, 50, and 100 ms RTT; all three delay placements
at nonzero RTT; uploads and downloads; one and eight streams per session. It also
checks 100 Mbit/s at 100 ms RTT for all placements and both transfer directions.
Every case alternates the execution order of direct HTTP/2, proxied HTTP/2, and
proxied HTTP/1.1 across repetitions. A case passes when:

- Median proxied HTTP/2 throughput reaches 90% of median direct HTTP/2 throughput.
- Median direct HTTP/2 throughput reaches 90% of nominal link rate.
- Queue drops, transfer errors, and payload validation errors are zero.

Throughput counts bytes consumed by the receiver during the measurement interval.
Upload counts come from the upstream server's loopback control socket. All
containers use the host's monotonic clock. Timed runs cancel their 1 TiB transfers
at the deadline.
The `cold` profile opens fresh TCP/TLS connections, transfers complete 1 KiB and
64 KiB bodies, and reports completion and first-byte times separately. The proxy's
certificate cache remains warm between connections.

`readers` measures slow readers, one paused stream alongside seven active
streams, and eight separate slow sessions, in both directions. The pause lasts
five seconds. Per-stream timestamps verify that the other streams still transfer
data in the pause's final second and that the paused stream resumes. Check whether
resident memory use (RSS) stabilizes, and compare single-session and multi-session
memory use. Use `--reader-case upload/sessions --seconds 90` to extend the
eight-session upload scenario; `download/slow` and `download/paused` select the
other patterns.

JSON reports include individual samples, case medians and ratios, queue counters,
route and offload settings, memory and CPU samples, tool versions, revision,
diff summary, and binary SHA-256. Keep raw files under `target/perf/`.
[RESULTS.md](RESULTS.md) records the measurements, benchmark limitations, and
default-window selection.
