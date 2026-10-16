# HTTP/2 receive-window measurements

Measured on 15–16 October 2026. The selected defaults are **32 MiB per stream**
and **64 MiB per connection**, applied independently to the client and upstream
HTTP/2 connections.

All 46 throughput cases passed. With the selected windows, the slow-reader tests
also passed. Resident memory use (RSS) stabilized near 319 MiB in the extended
eight-session upload test.

## Environment and method

- ARM64 Linux VM, 6 CPUs, 11.7 GiB RAM; Ubuntu kernel `6.8.0-106-generic`.
- Rust 1.99.0, release build, `h2` 0.4.14; Docker 29.9.0 and iproute2 6.1.0.
- Local Docker networks, streamed and validated payloads, TLS inspection, cache
  disabled. See [README.md](README.md) for the topology and commands.
- Five repetitions per case, alternating direct HTTP/2, proxied HTTP/2, and
  proxied HTTP/1.1; 2 seconds warmup and 5 seconds measured. Ratios compare case medians.
- Acceptance requires proxied HTTP/2 throughput >=90% of direct HTTP/2 throughput,
  direct HTTP/2 throughput >=90% of configured link rate, and zero queue drops,
  transfer errors, or payload validation errors.

The VM showed substantial TCP-startup and timer variability. Throughput timing
uses the shared monotonic clock. RTT calibration was changed from ping to a
monotonic UDP echo probe after a wall-clock correction produced an impossible
13 ms ping measurement on a path configured for 100 ms.

The final benchmark setup uses initial TCP congestion and receive windows of
16,384 segments at 1 Gbit/s and 2,048 at 100 Mbit/s. At 100 Mbit/s, the
16,384-segment setup produced direct throughput below the benchmark's validity threshold; 2,048
restored the expected throughput. The `cold` profile uses the kernel's
initial-window defaults. These adjustments are confined to the benchmark
containers; production TCP behavior is unchanged.

The reported 0 and 20 ms cases used kernel TCP startup defaults. Later cases used
the configured initial windows. Netem queue capacity increased from 65,536 to
262,144 packets during calibration. Raw reports retain failed calibrations and
runs where direct throughput fell below the validity threshold.

## Window selection

Single download, 1 Gbit/s, 100 ms upstream RTT. Entries show proxy Mbit/s and
percentage of the corresponding direct HTTP/2 median.

| Stream / connection | Kernel TCP startup | Controlled TCP startup |
|---|---:|---:|
| 65,535 / 65,535 bytes | 4.8 (0.5%) | 4.8 (0.5%) |
| 4 / 16 MiB | 225.5 (23.7%) | 222.3 (23.3%) |
| 8 / 32 MiB | 443.1 (46.7%) | 442.9 (46.5%) |
| 16 / 32 MiB | 827.6 (86.9%) | 884.5 (92.8%) |
| 32 / 64 MiB | Direct throughput below validity threshold | 947.3 (99.4%) |

The 16/32 MiB windows passed with the configured TCP initial windows but missed
the throughput target in a valid run using kernel TCP startup defaults. We chose
32/64 MiB to allow more data in flight.

These measurements do not establish bulk-transfer performance with the kernel's
default initial TCP windows at 32/64 MiB. In that test, direct HTTP/2 throughput
reached only 469 Mbit/s on the configured 1 Gbit/s link, below the benchmark's
validity threshold.

## Throughput matrix

The 46 throughput cases that met the benchmark's validity requirements contained
690 timed runs. The lowest proxy/direct median ratio was **99.34%**. Direct
HTTP/2 medians were 948.4–953.3 Mbit/s on the 1 Gbit/s link and 95.3 Mbit/s on
the 100 Mbit/s link. All reported cases had zero queue drops, transfer errors,
and payload validation errors.

Entries below are proxied HTTP/2 throughput as a percentage of direct HTTP/2.
The suffix is the number of streams in one session.

| Mbit/s | RTT ms | Delay placement | Download ×1 | Download ×8 | Upload ×1 | Upload ×8 |
|---:|---:|---|---:|---:|---:|---:|
| 1000 | 0 | upstream | 100.0% | 99.9% | 100.0% | 100.0% |
| 1000 | 20 | upstream | 99.9% | 99.9% | 99.8% | 99.9% |
| 1000 | 20 | downstream | 100.0% | 99.7% | 99.9% | 99.9% |
| 1000 | 20 | split | 100.0% | 99.7% | 100.0% | 99.9% |
| 1000 | 50 | upstream | 99.4% | 99.4% | 99.8% | 99.8% |
| 1000 | 50 | downstream | 99.4% | 99.4% | 99.8% | 99.8% |
| 1000 | 50 | split | 99.4% | 99.4% | 99.8% | 99.8% |
| 1000 | 100 | upstream | 99.4% | 99.3% | 100.0% | 100.0% |
| 1000 | 100 | downstream | 100.0% | 100.1% | 99.8% | 99.8% |
| 1000 | 100 | split | 99.4% | 99.4% | 99.8% | 99.8% |
| 100 | 100 | upstream | 99.4% | — | 99.8% | — |
| 100 | 100 | downstream | 99.4% | — | 99.8% | — |
| 100 | 100 | split | 99.4% | — | 99.8% | — |

All six 100 Mbit/s cases were repeated with the rate-scaled TCP initial window.
An earlier download case passed at 98.5% with the larger fixed TCP window; its
report is retained with the calibration results.

## Slow readers and memory

Each standard scenario runs for 2 seconds warmup plus 30 seconds measured.
Slow readers sleep 20 ms per received DATA frame. Frame sizes affect the byte
rate, so these scenarios measure backpressure and memory behavior. The paused
case suspends one of eight streams for five seconds.

Peak proxy RSS, in MiB:

| Direction | Scenario | Old windows | 32/64 MiB |
|---|---|---:|---:|
| Download | One slow stream | 11.8 | 45.2 |
| Download | Eight streams, one paused | 12.5 | 77.4 |
| Download | Eight slow sessions | 15.3 | 278.6 |
| Upload | One slow stream | 11.6 | 49.0 |
| Upload | Eight streams, one paused | 12.4 | 95.0 |
| Upload | Eight slow sessions | 15.5 | 293.4 |

With the new windows, all six progress checks passed. In both paused-stream tests,
the other seven streams continued transferring data during the pause's final
second, and the paused streams resumed. The old-window paused-download test failed
the independent progress check; its other five scenarios passed. All runs had zero queue drops,
transfer errors, and payload validation errors.

The eight-session upload scenario needed longer to settle. A 90-second run ended
near 299 MiB with RSS still rising. A 300-second measured run processed 570 MB,
peaked at 319.1 MiB, and stayed within 318.8–319.1 MiB during its final minute.
RSS changed by about 0.02 MiB in the last 30 seconds. All eight streams continued
transferring data.

RSS includes memory retained by the allocator and HTTP/2 frame bookkeeping.
Kernel TCP queues consume additional memory.

## Small-request latency

Five repetitions per size, fresh TCP/TLS sessions, warm proxy certificate cache,
1 Gbit/s and 100 ms upstream RTT. Times are median milliseconds.

| Body | Old HTTP/2 first byte | New HTTP/2 first byte | Old HTTP/2 completion | New HTTP/2 completion |
|---|---:|---:|---:|---:|
| 1 KiB | 320.0 | 320.8 | 320.2 | 320.9 |
| 64 KiB | 430.4 | 434.5 | 529.8 | 537.8 |

Direct HTTP/2 completion medians were 319.9/320.0 ms for 1 KiB and 525.3/533.8 ms for
64 KiB in the old/new runs respectively. The proxy's 64 KiB completion overhead
was therefore 4.5/4.0 ms. These samples show similar small-request latency; VM
timing noise limits finer comparisons. Queue drops, transfer errors, and payload
validation errors were zero.

## Repository checks

`cargo fmt --check`, `cargo clippy --all-targets --all-features`, and `cargo test`
passed; 588 tests ran successfully. Clippy retains the existing `fetch_update`
deprecation and `async_trait`-generated `double_must_use` warnings. New tests check
configuration bounds, advertised windows on client and upstream connections,
receive-window exhaustion and recovery, stream resets, and whether other streams
continue transferring data when one stalls.

## Raw reports

Raw JSON is retained locally under `target/perf/`. The baseline/candidate runs are
`final-{baseline,4-16,8-32,16-32}.json` and
`calibrated-{baseline,4-16,8-32,16-32}.json`. The throughput results come from
`final-full-32-64*.json`, `tcp-calibration-32-64.json`, and
`qualification-*.json`. Exploratory reports are also retained.

The HTTP/2 receive-window implementation was unchanged while the benchmark setup
was adjusted. SHA-256 hashes of the measured `h2-perf` release builds:

```text
7c905138c1fc161d4dcf00e93273ae4ae729e3cea653cc418429d1ed972bc1ad
8e9289319fe1da10388200c14c9e3654ac12ccc1bed3ef1685e23e7f3e52a11b
```

The second build adds monotonic UDP RTT calibration. Reports identify the
binary used, base revision `bde540ce1d516d2ae64d3f2ac4001e41b21dbd0c`, dirty-tree
diff summary, and tool-image digest.
