//! Compiling and running MP-SPDZ programs, and parsing what they print. Pure
//! orchestration: no protocol logic.

use std::fs;
use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::Instant;

use anyhow::{bail, Context, Result};
use regex::Regex;

/// Compiles `<name>.mpc` with the given arguments, reusing a cached schedule.
///
/// Returns the compiled program name, `<name>-<arg>-<arg>`.
pub fn compile(spdz_path: &Path, mpc_src: &Path, name: &str, args: &[String]) -> Result<String> {
    let src_dir = spdz_path.join("Programs").join("Source");
    fs::create_dir_all(&src_dir).with_context(|| format!("create {}", src_dir.display()))?;
    fs::copy(mpc_src, src_dir.join(format!("{name}.mpc")))
        .with_context(|| format!("copy {} into {}", mpc_src.display(), src_dir.display()))?;

    let full_name = std::iter::once(name.to_string())
        .chain(args.iter().cloned())
        .collect::<Vec<_>>()
        .join("-");

    let schedule = spdz_path
        .join("Programs")
        .join("Schedules")
        .join(format!("{full_name}.sch"));
    if schedule.exists() {
        println!("[mpc] cached compile for {full_name}");
        return Ok(full_name);
    }

    println!("[mpc] compiling {name} {} ...", args.join(" "));
    let started = Instant::now();
    let output = Command::new("./compile.py")
        .args(std::iter::once(name).chain(args.iter().map(String::as_str)))
        .current_dir(spdz_path)
        .output()
        .with_context(|| format!("run ./compile.py in {}", spdz_path.display()))?;
    if !output.status.success() {
        bail!(
            "./compile.py {name} {} failed ({})\nstderr:\n{}\nstdout:\n{}",
            args.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr),
            String::from_utf8_lossy(&output.stdout),
        );
    }
    println!(
        "[mpc] compile done ({} ms) -> {full_name}.sch",
        started.elapsed().as_millis()
    );
    Ok(full_name)
}

/// What each party wrote to its pipes.
pub struct PartyOutput {
    pub stdout: Vec<String>,
    pub stderr: Vec<String>,
}

/// Launches `parties` copies of `shamir-party.x` and waits for all of them.
///
/// Each pipe is drained on its own thread: MP-SPDZ is verbose under `-v` and a
/// party blocks once a pipe buffer fills.
pub fn run(spdz_path: &Path, full_name: &str, parties: usize) -> Result<PartyOutput> {
    println!("[mpc] launching {parties} parties: shamir-party.x {full_name}");
    let started = Instant::now();

    let mut children = Vec::with_capacity(parties);
    for party in 0..parties {
        let child = Command::new("./shamir-party.x")
            .args([
                "-v",
                "-N",
                &parties.to_string(),
                "-p",
                &party.to_string(),
                full_name,
            ])
            .current_dir(spdz_path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("spawn shamir-party.x -p {party}"))?;
        children.push(child);
    }

    let mut stdout = vec![String::new(); parties];
    let mut stderr = vec![String::new(); parties];
    let mut codes = Vec::with_capacity(parties);

    std::thread::scope(|scope| -> Result<()> {
        let mut readers = Vec::with_capacity(parties * 2);
        for child in &mut children {
            let out = child.stdout.take().expect("piped stdout");
            let err = child.stderr.take().expect("piped stderr");
            readers.push(scope.spawn(move || drain(out)));
            readers.push(scope.spawn(move || drain(err)));
        }

        for (i, reader) in readers.into_iter().enumerate() {
            let text = reader.join().expect("pipe reader thread")?;
            if i % 2 == 0 {
                stdout[i / 2] = text;
            } else {
                stderr[i / 2] = text;
            }
        }
        Ok(())
    })?;

    for (party, child) in children.iter_mut().enumerate() {
        let status = child
            .wait()
            .with_context(|| format!("wait for shamir-party.x -p {party}"))?;
        codes.push(status.code().unwrap_or(-1));
    }

    println!(
        "[mpc] done in {} ms (codes: [{}])",
        started.elapsed().as_millis(),
        codes
            .iter()
            .map(i32::to_string)
            .collect::<Vec<_>>()
            .join(",")
    );

    if codes.iter().any(|c| *c != 0) {
        bail!(
            "MP-SPDZ failed.\nstderr (p0):\n{}\nstdout (p0):\n{}",
            stderr.first().map_or("", String::as_str),
            stdout.first().map_or("", String::as_str),
        );
    }

    Ok(PartyOutput { stdout, stderr })
}

fn drain<R: Read>(mut pipe: R) -> Result<String> {
    let mut buf = Vec::new();
    pipe.read_to_end(&mut buf)?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Reads the `row_<i>=<0|1>` predicate lines party 0 prints.
pub fn parse_predicates(stdout: &str, n: usize) -> Result<Vec<bool>> {
    static ROW: OnceLock<Regex> = OnceLock::new();
    let row = ROW.get_or_init(|| Regex::new(r"^row_(\d+)=(\d)").expect("valid regex"));

    let mut out = vec![None; n];
    for line in stdout.lines() {
        if let Some(caps) = row.captures(line) {
            let index: usize = caps[1].parse().context("predicate row index")?;
            if index < n {
                out[index] = Some(&caps[2] == "1");
            }
        }
    }

    out.into_iter()
        .collect::<Option<Vec<bool>>>()
        .with_context(|| format!("failed to parse all {n} predicate rows from MP-SPDZ stdout"))
}

/// Timing and bandwidth counters MP-SPDZ reports under `-v`.
#[derive(Clone, Copy, Debug, Default)]
pub struct SpdzStats {
    pub total_ms: Option<f64>,
    pub online_ms: Option<f64>,
    pub offline_ms: Option<f64>,
    pub online_bytes: Option<u64>,
    pub online_rounds: Option<u64>,
    pub offline_bytes: Option<u64>,
    pub offline_rounds: Option<u64>,
    pub data_sent_bytes: Option<u64>,
    pub data_sent_rounds: Option<u64>,
    pub global_data_sent_bytes: Option<u64>,
}

fn seconds_to_ms(raw: &str) -> Option<f64> {
    raw.parse::<f64>().ok().map(|s| s * 1000.0)
}

fn to_bytes(value: &str, unit: &str) -> Option<u64> {
    let v: f64 = value.parse().ok()?;
    let scale = match unit.chars().next().map(|c| c.to_ascii_lowercase()) {
        Some('g') => 1024f64.powi(3),
        Some('m') => 1024f64.powi(2),
        Some('k') => 1024.0,
        _ => 1.0,
    };
    Some((v * scale).round() as u64)
}

/// Parses party 0's combined stdout+stderr.
pub fn parse_spdz_stats(combined: &str) -> SpdzStats {
    static PATTERNS: OnceLock<[Regex; 5]> = OnceLock::new();
    let [total, online, phases, data_sent, global] = PATTERNS.get_or_init(|| {
        [
            Regex::new(r"\bTime\s*=\s*([\d.]+)(?:\s*seconds?)?\b").expect("valid regex"),
            Regex::new(r"\bTime1\s*=\s*([\d.]+)(?:\s*seconds?)?\b").expect("valid regex"),
            Regex::new(
                r"(?i)Spent\s+([\d.]+)\s*seconds?\s*\(([\d.]+)\s*([kKmMgG]?B),\s*(\d+)\s*rounds?\)\s*on\s*the\s*online\s*phase\s*and\s*([\d.]+)\s*seconds?\s*\(([\d.]+)\s*([kKmMgG]?B),\s*(\d+)\s*rounds?\)\s*on\s*the\s*preprocessing(?:/offline)?\s*phase",
            )
            .expect("valid regex"),
            Regex::new(r"Data sent\s*=\s*([\d.]+)\s*([kKmMgG]?B)\s*in\s*~?(\d+)\s*rounds?")
                .expect("valid regex"),
            Regex::new(r"Global data sent\s*=\s*([\d.]+)\s*([kKmMgG]?B)").expect("valid regex"),
        ]
    });

    let mut stats = SpdzStats::default();

    if let Some(caps) = total.captures(combined) {
        stats.total_ms = seconds_to_ms(&caps[1]);
    }
    if let Some(caps) = online.captures(combined) {
        stats.online_ms = seconds_to_ms(&caps[1]);
    }
    if let Some(caps) = phases.captures(combined) {
        stats.online_ms = seconds_to_ms(&caps[1]);
        stats.online_bytes = to_bytes(&caps[2], &caps[3]);
        stats.online_rounds = caps[4].parse().ok();
        stats.offline_ms = seconds_to_ms(&caps[5]);
        stats.offline_bytes = to_bytes(&caps[6], &caps[7]);
        stats.offline_rounds = caps[8].parse().ok();
    }
    if let Some(caps) = data_sent.captures(combined) {
        stats.data_sent_bytes = to_bytes(&caps[1], &caps[2]);
        stats.data_sent_rounds = caps[3].parse().ok();
    }
    if let Some(caps) = global.captures(combined) {
        stats.global_data_sent_bytes = to_bytes(&caps[1], &caps[2]);
    }

    stats
}

/// Writes `Player-Data/Input-P<i>-0` for a three-party run.
///
/// Party 0 contributes the flattened upper triangle of `M'`; the other two
/// parties contribute nothing.
pub fn write_player_inputs(spdz_path: &Path, lines: &[String], parties: usize) -> Result<()> {
    let dir = spdz_path.join("Player-Data");
    fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;

    let mut body = lines.join("\n");
    body.push('\n');
    fs::write(dir.join("Input-P0-0"), body).context("write Input-P0-0")?;
    for party in 1..parties {
        fs::write(dir.join(format!("Input-P{party}-0")), "")
            .with_context(|| format!("write Input-P{party}-0"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_predicate_rows() {
        let stdout = "noise\nrow_0=1\nrow_2=0\nrow_1=1\nmore noise\n";
        assert_eq!(parse_predicates(stdout, 3).unwrap(), [true, true, false]);
        assert!(parse_predicates(stdout, 4).is_err());
    }

    #[test]
    fn reads_phase_timings_and_bandwidth() {
        let combined = concat!(
            "Time = 1.5 seconds\n",
            "Time1 = 0.25 seconds\n",
            "Spent 0.4 seconds (12.5 MB, 30 rounds) on the online phase ",
            "and 1.1 seconds (2 GB, 7 rounds) on the preprocessing phase\n",
            "Data sent = 512 kB in ~40 rounds\n",
            "Global data sent = 1.5 MB\n",
        );
        let stats = parse_spdz_stats(combined);
        assert_eq!(stats.total_ms, Some(1500.0));
        assert_eq!(stats.online_ms, Some(400.0));
        assert_eq!(stats.offline_ms, Some(1100.0));
        assert_eq!(stats.online_bytes, Some((12.5 * 1024.0 * 1024.0) as u64));
        assert_eq!(stats.online_rounds, Some(30));
        assert_eq!(stats.offline_bytes, Some(2 * 1024 * 1024 * 1024));
        assert_eq!(stats.offline_rounds, Some(7));
        assert_eq!(stats.data_sent_bytes, Some(512 * 1024));
        assert_eq!(stats.data_sent_rounds, Some(40));
        assert_eq!(stats.global_data_sent_bytes, Some(1024 * 1024 + 512 * 1024));
    }

    #[test]
    fn missing_counters_stay_unset() {
        let stats = parse_spdz_stats("nothing useful here");
        assert!(stats.total_ms.is_none());
        assert!(stats.online_bytes.is_none());
    }
}
