use std::{fs, path::Path};

pub(super) fn budget(explicit: Option<u64>) -> (u64, &'static str) {
    if let Some(bytes) = explicit {
        return (bytes, "configured");
    }
    let ram = fs::read_to_string("/proc/meminfo").ok().and_then(|text| {
        text.lines().find_map(|line| {
            line.strip_prefix("MemTotal:")?
                .split_whitespace()
                .next()?
                .parse::<u64>()
                .ok()?
                .checked_mul(1024)
        })
    });
    match detect_limit() {
        Ok(Some(limit)) => (limit.min(ram.unwrap_or(limit)) / 2, "cgroup"),
        result => {
            if let Err(error) = result {
                tracing::warn!(%error, "cannot detect HTTP/2 memory limit; using fallback budget");
            }
            (
                ram.map_or(256 << 20, |bytes| (bytes / 4).min(256 << 20)),
                "host fallback",
            )
        }
    }
}
fn unescape(path: &str) -> String {
    path.replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
}
fn detect_limit() -> std::io::Result<Option<u64>> {
    let membership = fs::read_to_string("/proc/self/cgroup")?;
    let mounts = fs::read_to_string("/proc/self/mountinfo")?;
    limits_from_mounts(&membership, &mounts)
}
fn limits_from_mounts(membership: &str, mounts: &str) -> std::io::Result<Option<u64>> {
    let mut limit = None;
    for line in membership.lines() {
        let parts: Vec<_> = line.splitn(3, ':').collect();
        if parts.len() != 3 {
            continue;
        }
        let v2 = parts[0] == "0" && parts[1].is_empty();
        if !v2 && !parts[1].split(',').any(|c| c == "memory") {
            continue;
        }
        for mount in mounts.lines() {
            let Some((left, right)) = mount.split_once(" - ") else {
                continue;
            };
            let fields: Vec<_> = left.split_whitespace().collect();
            let types: Vec<_> = right.split_whitespace().collect();
            if fields.len() < 5 || types.len() < 3 {
                continue;
            }
            if !(v2 && types[0] == "cgroup2"
                || !v2 && types[0] == "cgroup" && types[2].split(',').any(|c| c == "memory"))
            {
                continue;
            }
            let root = unescape(fields[3]);
            let mountpoint = unescape(fields[4]);
            let Ok(relative) = Path::new(parts[2]).strip_prefix(&root) else {
                continue;
            };
            let base = Path::new(&mountpoint);
            let mut path = base.join(relative);
            loop {
                let file = path.join(if v2 {
                    "memory.max"
                } else {
                    "memory.limit_in_bytes"
                });
                match fs::read_to_string(&file) {
                    Ok(value) => {
                        if let Some(bytes) = parse_limit(&value) {
                            limit = Some(limit.map_or(bytes, |old: u64| old.min(bytes)));
                        }
                    }
                    Err(e) if path == base && e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e),
                }
                if path == base || !path.pop() {
                    break;
                }
            }
        }
    }
    Ok(limit)
}
fn parse_limit(value: &str) -> Option<u64> {
    value.trim().parse::<u64>().ok().filter(|v| *v < (1 << 60))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn detects_visible_ancestor_limits_for_both_cgroup_versions() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("service/child")).unwrap();
        for (v2, name, unlimited) in [
            (true, "memory.max", "max"),
            (false, "memory.limit_in_bytes", "9223372036854771712"),
        ] {
            std::fs::write(root.join(name), unlimited).unwrap();
            std::fs::write(root.join("service").join(name), "1048576").unwrap();
            std::fs::write(root.join("service/child").join(name), "2097152").unwrap();
            let (membership, kind, opts) = if v2 {
                ("0::/service/child", "cgroup2", "rw")
            } else {
                ("4:cpu,memory:/service/child", "cgroup", "rw,cpu,memory")
            };
            let mounts = format!("1 2 0:1 / {} rw - {kind} none {opts}", root.display());
            assert_eq!(
                limits_from_mounts(membership, &mounts).unwrap(),
                Some(1048576)
            );
            let mounts = format!(
                "1 2 0:1 /service {} rw - {kind} none {opts}",
                root.join("service").display()
            );
            assert_eq!(
                limits_from_mounts(membership, &mounts).unwrap(),
                Some(1048576)
            );
        }
    }
    #[test]
    fn unlimited_and_finite_limits() {
        assert_eq!(parse_limit("max\n"), None);
        assert_eq!(parse_limit("9223372036854771712"), None);
        assert_eq!(parse_limit("1048576\n"), Some(1048576));
        assert_eq!(budget(Some(123)), (123, "configured"));
    }
}
