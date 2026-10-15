#!/usr/bin/env python3
"""Controlled HTTP/2 benchmarks. All network changes are inside owned containers."""
import argparse
import hashlib
import json
import pathlib
import shlex
import statistics
import subprocess
import sys
import time
import uuid

ROOT = pathlib.Path(__file__).resolve().parents[2]
MIB = 1024 * 1024
TCP_INITIAL_WINDOW = 16384  # Segments: covers the 1 Gbit/s, 100 ms bandwidth-delay product.


def command(*args, check=True):
    result = subprocess.run(list(map(str, args)), capture_output=True, text=True)
    if check and result.returncode:
        raise RuntimeError(f"{shlex.join(list(map(str, args)))}\n{result.stderr}\n{result.stdout}")
    return result.stdout.strip()


class Rig:
    def __init__(self, binary, image, receive_window):
        self.prefix = "exfilguard-h2-" + uuid.uuid4().hex[:10]
        self.binary = binary
        self.image = image
        self.receive_window = receive_window
        self.containers = []
        self.networks = []
        self.volume = None
        self.proxy_running = False

    def exec(self, node, *args, check=True):
        return command("docker", "exec", self.prefix + "-" + node, *args, check=check)

    def start(self):
        for name, subnet in [("front", "10.221.1.0/24"), ("back", "10.221.2.0/24")]:
            network = self.prefix + "-" + name
            command("docker", "network", "create", "--internal", "--subnet", subnet, network)
            self.networks.append(network)
        self.volume = command("docker", "volume", "create", self.prefix + "-data")
        for node, network, address in [
            ("client", "front", "10.221.1.2"),
            ("proxy", "front", "10.221.1.3"),
            ("origin", "back", "10.221.2.2"),
        ]:
            name = self.prefix + "-" + node
            command("docker", "create", "--name", name, "--cap-add", "NET_ADMIN",
                    "--add-host", "origin.perf.test:10.221.2.2",
                    "--network", self.prefix + "-" + network, "--ip", address,
                    "--sysctl", "net.ipv4.ip_forward=1",
                    "--sysctl", "net.ipv4.tcp_rmem=4096 33554432 67108864",
                    "--sysctl", "net.ipv4.tcp_wmem=4096 33554432 67108864",
                    "--sysctl", "net.ipv4.tcp_no_metrics_save=1",
                    "--mount", f"type=volume,source={self.volume},target=/data", self.image)
            self.containers.append(name)
            if node == "proxy":
                command("docker", "network", "connect", "--ip", "10.221.2.3", self.prefix + "-back", name)
            command("docker", "cp", self.binary, name + ":/h2-perf")
            command("docker", "start", name)
        self.exec("client", "ip", "route", "add", "10.221.2.0/24", "via", "10.221.1.3")
        self.exec("origin", "ip", "route", "add", "10.221.1.0/24", "via", "10.221.2.3")
        self.interfaces = []
        for node in ["client", "proxy", "origin"]:
            for interface in json.loads(self.exec(node, "ip", "-j", "address")):
                networks = [a["local"] for a in interface.get("addr_info", []) if a["family"] == "inet"]
                if not any(a.startswith("10.221.") for a in networks):
                    continue
                device = interface["ifname"]
                self.exec(node, "ethtool", "-K", device, "tso", "off", "gso", "off", "gro", "off")
                leg = "front" if any(a.startswith("10.221.1.") for a in networks) else "back"
                self.interfaces.append((node, device, leg))
        self.exec("origin", "/h2-perf", "init")
        self.background("origin", ["/h2-perf", "origin", "--listen", "10.221.2.2:8443",
                                   "--receive-window", str(self.receive_window)])
        for _ in range(100):
            try:
                self.stats()
                break
            except RuntimeError:
                time.sleep(0.1)
        else:
            raise RuntimeError("origin did not start")

    def tcp_windows(self, segments):
        result = {}
        for node in ["client", "proxy", "origin"]:
            routes = json.loads(self.exec(node, "ip", "-j", "route", "show"))
            for route in routes:
                if route.get("dst") not in ["10.221.1.0/24", "10.221.2.0/24"]:
                    continue
                args = ["ip", "route", "change", route["dst"], "dev", route["dev"]]
                if "gateway" in route:
                    args += ["via", route["gateway"]]
                if "scope" in route:
                    args += ["scope", route["scope"]]
                if "prefsrc" in route:
                    args += ["src", route["prefsrc"]]
                args += ["initcwnd", str(segments), "initrwnd", str(segments)]
                self.exec(node, *args)
            result[node] = json.loads(self.exec(node, "ip", "-j", "route", "show"))
        return result

    def background(self, node, args):
        command("docker", "exec", "-d", self.prefix + "-" + node, "sh", "-c",
                "exec " + shlex.join(args) + f" >/data/{node}.stdout 2>/data/{node}.stderr")

    def proxy(self, pair):
        if self.proxy_running:
            self.exec("proxy", "pkill", "-x", "h2-perf")
            self.proxy_running = False
            for _ in range(100):
                if ":3128" not in self.exec("proxy", "ss", "-ltn"):
                    break
                time.sleep(0.1)
            else:
                raise RuntimeError("previous proxy did not stop")
        self.background("proxy", ["/h2-perf", "proxy", "--stream-window", str(pair[0]),
                                   "--connection-window", str(pair[1])])
        for _ in range(100):
            if ":3128" in self.exec("proxy", "ss", "-ltn"):
                self.proxy_running = True
                return
            time.sleep(0.1)
        raise RuntimeError("proxy did not start: " + self.exec("proxy", "cat", "/data/proxy.stderr"))

    def shape(self, rate, rtt, placement):
        for node, device, leg in self.interfaces:
            total = rtt if placement == {"front": "downstream", "back": "upstream"}[leg] else 0
            if placement == "split":
                total = rtt / 2
            self.exec(node, "tc", "qdisc", "replace", "dev", device, "root", "netem",
                      "limit", "262144", "delay", f"{total / 2}ms", "rate", f"{rate}mbit")
        # UDP echo validates path delay with CLOCK_MONOTONIC, including routing.
        # Keep every sample, including neighbour discovery and scheduling jitter.
        probes = []
        for _ in range(3):
            probe = json.loads(self.exec("client", "/h2-perf", "probe"))
            probes.append(probe)
            # Validate the propagation-delay floor; VM scheduling adds jitter.
            # Preserve individual samples for reviewing that noise with the results.
            samples = probe["rtt_ms"]
            if any(sample is None for sample in samples):
                continue
            minimum = min(samples)
            if abs(minimum - rtt) <= max(5, rtt * 0.1):
                return probes
        raise RuntimeError(f"unexpected path RTT after three probes (requested {rtt}ms): {probes}")

    def stats(self):
        return json.loads(self.exec("origin", "/h2-perf", "stats"))

    def resources(self):
        return json.loads(self.exec("proxy", "sh", "-c", "pid=$(pidof h2-perf); "
            "awk '/VmRSS:/ {rss=$2} /VmHWM:/ {peak=$2} END {printf \"{\\\"rss_kib\\\":%d,\\\"peak_kib\\\":%d}\",rss,peak}' /proc/$pid/status"))

    def qdiscs(self):
        return {f"{node}/{device}": json.loads(self.exec(node, "tc", "-s", "-j", "qdisc", "show", "dev", device))
                for node, device, _ in self.interfaces}

    def run(self, mode, upload, streams, args, extra=()):
        before = self.stats()
        client_args = ["docker", "exec", self.prefix + "-client", "/h2-perf", "client",
                       "--receive-window", str(self.receive_window),
                       "--streams", str(streams), "--warmup", str(args.warmup),
                       "--seconds", str(args.seconds), "--protocol", "h1" if mode == "proxy_h1" else "h2"]
        if mode != "direct_h2":
            client_args += ["--proxy", "10.221.1.3:3128"]
        if upload:
            client_args += ["--upload"]
        client_args += list(extra)
        proc = subprocess.Popen(client_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        samples = []
        try:
            while proc.poll() is None:
                samples.append({"time": time.monotonic(), **self.resources(),
                    "cpu": self.exec("proxy", "sh", "-c", "pid=$(pidof h2-perf); cat /proc/$pid/stat")})
                time.sleep(0.5)
            stdout, stderr = proc.communicate()
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
        if proc.returncode:
            raise RuntimeError(f"client failed: {stderr}\n{stdout}")
        result = json.loads(stdout)
        after = self.stats()
        if upload:
            result["bytes"] = after["bytes"] - before["bytes"]
            result["stream_progress"] = after["stream_progress"][len(before["stream_progress"]):]
        if result["errors"] or after["errors"] != before["errors"]:
            raise RuntimeError(f"transfer failed: {result}\n" + self.exec("proxy", "cat", "/data/proxy.stderr"))
        result.update(mode=mode, resources=samples, mbps=result["bytes"] * 8 / result["seconds"] / 1e6)
        return result

    def close(self):
        for name in reversed(self.containers):
            command("docker", "rm", "-f", name, check=False)
        for name in reversed(self.networks):
            command("docker", "network", "rm", name, check=False)
        if self.volume:
            command("docker", "volume", "rm", self.volume, check=False)


def matrix(profile):
    if profile == "cold":
        return []
    if profile == "smoke":
        return [(1000, 0, "upstream", upload, 1) for upload in [False, True]]
    if profile == "screen":
        return [(1000, 100, "downstream" if upload else "upstream", upload, streams)
                for streams in [1, 8] for upload in [False, True]]
    cases = [(1000, rtt, placement, upload, streams)
             for rtt in [0, 20, 50, 100]
             for placement in (["upstream"] if rtt == 0 else ["upstream", "downstream", "split"])
             for upload in [False, True] for streams in [1, 8]]
    cases += [(100, 100, placement, upload, 1)
              for placement in ["upstream", "downstream", "split"] for upload in [False, True]]
    return cases


def case_name(case):
    rate, rtt, placement, upload, streams = case
    return f"{rate}/{rtt}/{placement}/{'upload' if upload else 'download'}/{streams}"


def queue_drop_count(qdiscs):
    return sum(q.get("drops", 0) for queues in qdiscs.values() for q in queues)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=pathlib.Path, default=ROOT / "target/release/examples/h2-perf")
    parser.add_argument("--image", default="exfilguard-h2-perf-tools")
    parser.add_argument("--profile", choices=["smoke", "screen", "full", "readers", "cold"], default="screen")
    parser.add_argument("--windows", default="32/64", help="stream/connection MiB; 'baseline' uses 65535 bytes")
    parser.add_argument("--repetitions", type=int, default=5)
    parser.add_argument("--fail-fast", action="store_true", help="stop after the first failing case")
    parser.add_argument("--case", action="append", dest="case_filter",
                        help="select rate/RTT/placement/upload|download/streams; repeat to select several")
    parser.add_argument("--reader-case", choices=[f"{direction}/{kind}"
                        for direction in ["download", "upload"] for kind in ["slow", "paused", "sessions"]],
                        help="select one reader-stress scenario")
    parser.add_argument("--warmup", type=int, default=2)
    parser.add_argument("--tcp-initial-window", type=int,
                        help="initial TCP window in segments; default scales with rate, 0 uses kernel defaults")
    parser.add_argument("--seconds", type=int, default=5)
    parser.add_argument("--output", type=pathlib.Path, default=ROOT / "target/perf/h2-results.json")
    args = parser.parse_args()
    try:
        pair = (65535, 65535) if args.windows == "baseline" else tuple(int(n) * MIB for n in args.windows.split("/"))
    except ValueError:
        parser.error("windows must be stream/connection MiB or 'baseline'")
    if len(pair) != 2 or not all(65535 <= value <= 2147483647 for value in pair):
        parser.error("provide two window sizes, each between 65535 and 2147483647 bytes")
    if args.repetitions < 1 or args.seconds < 1 or args.warmup < 0:
        parser.error("repetitions/seconds must be positive and warmup nonnegative")
    if args.tcp_initial_window is not None and not 0 <= args.tcp_initial_window <= 4294967295:
        parser.error("TCP initial window must fit an unsigned 32-bit route metric")
    if args.reader_case and args.profile != "readers":
        parser.error("--reader-case requires --profile readers")
    cases = matrix(args.profile)
    if args.case_filter:
        if args.profile in ["readers", "cold"] or not set(args.case_filter) <= {case_name(case) for case in cases}:
            parser.error("--case must name a throughput case in the selected profile")
        cases = [case for case in cases if case_name(case) in args.case_filter]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    rig = Rig(args.binary.resolve(), args.image, 65535 if args.profile == "readers" else 128 * MIB)
    report = {"revision": command("git", "-C", ROOT, "rev-parse", "HEAD"),
              "rig": rig.prefix,
              "binary_sha256": hashlib.file_digest(args.binary.open("rb"), "sha256").hexdigest(),
              "diff": command("git", "-C", ROOT, "diff", "--stat"),
              "windows": pair, "profile": args.profile,
              "case_filter": args.case_filter,
              "reader_case": args.reader_case,
              "endpoint_stream_window": rig.receive_window,
              "clock": "CLOCK_MONOTONIC",
              "warmup": args.warmup, "seconds": args.seconds, "repetitions": args.repetitions,
              "tcp_initial_window_override": args.tcp_initial_window,
              "rustc": command("rustc", "--version", "--verbose"),
              "image": command("docker", "image", "inspect", "--format", "{{.Id}}", args.image),
              "hardware": command("docker", "info", "--format", "CPUs={{.NCPU}} Memory={{.MemTotal}}"),
              "docker": command("docker", "version", "--format", "{{json .Server}}"),
              "runs": [], "cases": []}

    def save():
        args.output.write_text(json.dumps(report, indent=2) + "\n")

    try:
        rig.start()
        initial_window = TCP_INITIAL_WINDOW if args.tcp_initial_window is None else args.tcp_initial_window
        report["tcp_routes"] = rig.tcp_windows(0 if args.profile == "cold" else initial_window)
        report["tc"] = rig.exec("client", "tc", "-V")
        report["kernel"] = rig.exec("client", "uname", "-a")
        report["clock_ticks_per_second"] = int(rig.exec("proxy", "getconf", "CLK_TCK"))
        report["interfaces"] = {f"{node}/{device}": rig.exec(node, "ethtool", "-k", device)
                                for node, device, _ in rig.interfaces}
        report["tcp_buffers"] = rig.exec("client", "sysctl", "net.ipv4.tcp_rmem", "net.ipv4.tcp_wmem", "net.ipv4.tcp_no_metrics_save")
        rig.proxy(pair)
        if args.profile == "readers":
            report["rtt_probes"] = rig.shape(1000, 20, "upstream")
            for upload in [False, True]:
                for kind, streams, sessions, delay, pause in [
                    ("slow", 1, 1, 20, 0), ("paused", 8, 1, 0, 5000), ("sessions", 1, 8, 20, 0)
                ]:
                    if args.reader_case and args.reader_case != f"{'upload' if upload else 'download'}/{kind}":
                        continue
                    rig.proxy(pair)
                    result = rig.run("proxy_h2", upload, streams, args,
                        ["--sessions", str(sessions), "--read-delay-ms", str(delay), "--pause-ms", str(pause)])
                    result.update(upload=upload, streams=streams, sessions=sessions, delay=delay, pause=pause)
                    result["qdiscs"] = rig.qdiscs()
                    result["queue_drops"] = queue_drop_count(result["qdiscs"])
                    progress = result["stream_progress"]
                    progress_ok = len(progress) == streams * sessions and all(p["bytes"] > 0 for p in progress)
                    if pause:
                        first_times = [(p["first_ns"] - result["started_ns"]) / 1e9 for p in progress]
                        active = [p for p, first in zip(progress, first_times) if first < pause / 1000]
                        progress_ok &= bool(first_times) and min(first_times) < pause / 1000 <= max(first_times)
                        progress_ok &= len(active) == streams * sessions - sessions
                        progress_ok &= all(p["last_during_pause_ns"] >= result["started_ns"] + (pause - 1000) * 1_000_000
                                           for p in active)
                    result["progress_passed"] = progress_ok
                    report["runs"].append(result)
                    save()
                    print(json.dumps({k: v for k, v in result.items() if k not in ["resources", "qdiscs"]}), flush=True)
        else:
            for rate, rtt, placement, upload, streams in cases:
                initial_window = args.tcp_initial_window
                if initial_window is None:
                    # Round a rate-proportional budget up to a power of two.
                    segments = max(1, TCP_INITIAL_WINDOW * rate // 1000)
                    initial_window = 1 << (segments - 1).bit_length()
                rig.tcp_windows(initial_window)
                case = dict(rate=rate, rtt=rtt, placement=placement, upload=upload, streams=streams,
                            tcp_initial_window=initial_window)
                probes = rig.shape(rate, rtt, placement)
                runs = []
                for repetition in range(args.repetitions):
                    modes = ["direct_h2", "proxy_h2", "proxy_h1"]
                    if repetition % 2:
                        modes.reverse()
                    for mode in modes:
                        result = rig.run(mode, upload, streams, args)
                        result.update(case, repetition=repetition)
                        runs.append(result)
                        report["runs"].append(result)
                        save()
                medians = {mode: statistics.median(r["mbps"] for r in runs if r["mode"] == mode)
                           for mode in ["direct_h2", "proxy_h2", "proxy_h1"]}
                qdiscs = rig.qdiscs()
                drops = queue_drop_count(qdiscs)
                valid = medians["direct_h2"] >= rate * 0.9 and drops == 0
                ratio = medians["proxy_h2"] / medians["direct_h2"] if medians["direct_h2"] else 0
                summary = dict(case, medians=medians, ratio=ratio, valid=valid, passed=valid and ratio >= 0.9,
                               rtt_probes=probes, qdiscs=qdiscs)
                report["cases"].append(summary)
                save()
                print(json.dumps({k: v for k, v in summary.items() if k not in ["rtt_probes", "qdiscs"]}), flush=True)
                if args.fail_fast and not summary["passed"]:
                    break
        # Cold completion is separate from the throughput acceptance ratio.
        if args.profile in ["full", "cold"]:
            report["cold_tcp_routes"] = rig.tcp_windows(0)
            report["cold_rtt_probes"] = rig.shape(1000, 100, "upstream")
            report["cold"] = []
            for size in [1024, 65536]:
                for repetition in range(args.repetitions):
                    modes = ["direct_h2", "proxy_h2", "proxy_h1"]
                    for mode in (list(reversed(modes)) if repetition % 2 else modes):
                        result = rig.run(mode, False, 1, args, ["--bytes", str(size)])
                        result.update(size=size, repetition=repetition)
                        report["cold"].append(result)
            report["cold_qdiscs"] = rig.qdiscs()
            if queue_drop_count(report["cold_qdiscs"]):
                raise RuntimeError("queue drops during cold transfers")
            save()
    except BaseException as error:
        report["error"] = repr(error)
        save()
        raise
    finally:
        rig.close()
    if report["cases"] and not all(case["passed"] for case in report["cases"]):
        sys.exit(1)
    if any(run.get("progress_passed") is False for run in report["runs"]):
        sys.exit(1)
    if any(run.get("queue_drops", 0) for run in report["runs"]):
        sys.exit(1)


if __name__ == "__main__":
    main()
